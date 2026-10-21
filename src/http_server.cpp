#include "robot_ota/http_server.h"

#include <sys/socket.h>
#include <sys/time.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/optional.hpp>
#include <json/json.h>

#include "robot_ota/errors.h"
#include "robot_ota/util.h"

namespace robot_ota {
namespace {

namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

constexpr const char* kServerName = "robot-ota-server/1.0";

std::string json_to_string(const Json::Value& value) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  builder["emitUTF8"] = true;
  std::string out = Json::writeString(builder, value);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
    out.pop_back();
  }
  return out;
}

http::response<http::string_body> make_json_response(http::status status,
                                                     unsigned version,
                                                     bool keep_alive,
                                                     const Json::Value& body) {
  http::response<http::string_body> response{status, version};
  response.set(http::field::server, kServerName);
  response.set(http::field::content_type, "application/json; charset=utf-8");
  response.set(http::field::cache_control, "no-store");
  response.set("X-Content-Type-Options", "nosniff");
  response.keep_alive(keep_alive);
  response.body() = json_to_string(body);
  response.prepare_payload();
  return response;
}

Json::Value make_error_body(const std::string& code,
                            const std::string& message) {
  Json::Value root;
  root["error"]["code"] = code;
  root["error"]["message"] = message;
  return root;
}

bool is_timeout_error(const boost::system::error_code& ec) {
  return ec == net::error::would_block || ec == net::error::try_again ||
         ec == net::error::timed_out;
}

bool starts_with_ci(const std::string& value, const std::string& prefix) {
  if (value.size() < prefix.size()) {
    return false;
  }
  for (size_t i = 0; i < prefix.size(); ++i) {
    const unsigned char a = static_cast<unsigned char>(value[i]);
    const unsigned char b = static_cast<unsigned char>(prefix[i]);
    const unsigned char lower_a =
        (a >= 'A' && a <= 'Z') ? static_cast<unsigned char>(a - 'A' + 'a') : a;
    const unsigned char lower_b =
        (b >= 'A' && b <= 'Z') ? static_cast<unsigned char>(b - 'A' + 'a') : b;
    if (lower_a != lower_b) {
      return false;
    }
  }
  return true;
}

bool equals_ci(const beast::string_view& value, const char* expected) {
  const size_t expected_size = std::char_traits<char>::length(expected);
  if (value.size() != expected_size) {
    return false;
  }
  for (size_t i = 0; i < expected_size; ++i) {
    unsigned char a = static_cast<unsigned char>(value[i]);
    unsigned char b = static_cast<unsigned char>(expected[i]);
    if (a >= 'A' && a <= 'Z') {
      a = static_cast<unsigned char>(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
      b = static_cast<unsigned char>(b - 'A' + 'a');
    }
    if (a != b) {
      return false;
    }
  }
  return true;
}

enum class RouteKind {
  None,
  DeviceInfo,
  CreateSession,
  GetSession,
  PatchPayload,
  Install,
};

struct Route {
  RouteKind kind = RouteKind::None;
  std::string session_id;
};

const char* allow_for(RouteKind kind) {
  switch (kind) {
    case RouteKind::DeviceInfo:
    case RouteKind::GetSession:
      return "GET";
    case RouteKind::CreateSession:
    case RouteKind::Install:
      return "POST";
    case RouteKind::PatchPayload:
      return "PATCH, HEAD";
    case RouteKind::None:
      break;
  }
  return "";
}

bool method_allowed(RouteKind kind, http::verb verb) {
  switch (kind) {
    case RouteKind::DeviceInfo:
    case RouteKind::GetSession:
      return verb == http::verb::get;
    case RouteKind::CreateSession:
    case RouteKind::Install:
      return verb == http::verb::post;
    case RouteKind::PatchPayload:
      return verb == http::verb::patch || verb == http::verb::head;
    case RouteKind::None:
      return false;
  }
  return false;
}

Route parse_route(const std::string& target) {
  std::string path = target;
  const size_t query = path.find('?');
  if (query != std::string::npos) {
    path.resize(query);
  }

  Route route;
  if (path == "/ota/v1/device-info") {
    route.kind = RouteKind::DeviceInfo;
    return route;
  }
  if (path == "/ota/v1/sessions") {
    route.kind = RouteKind::CreateSession;
    return route;
  }

  const std::string prefix = "/ota/v1/sessions/";
  if (path.compare(0, prefix.size(), prefix) != 0) {
    return route;
  }
  const std::string rest = path.substr(prefix.size());
  if (rest.empty()) {
    return route;
  }
  const size_t slash = rest.find('/');
  if (slash == std::string::npos) {
    route.kind = RouteKind::GetSession;
    route.session_id = rest;
    return route;
  }

  route.session_id = rest.substr(0, slash);
  const std::string tail = rest.substr(slash + 1);
  if (route.session_id.empty()) {
    return Route{};
  }
  if (tail == "payload") {
    route.kind = RouteKind::PatchPayload;
  } else if (tail == "install") {
    route.kind = RouteKind::Install;
  } else {
    return Route{};
  }
  return route;
}

Json::Value parse_json_body(const std::vector<uint8_t>& body) {
  if (body.empty()) {
    throw OtaError(400, "INVALID_REQUEST", "request body is empty");
  }
  Json::CharReaderBuilder builder;
  builder["collectComments"] = false;
  builder["strictMode"] = true;
  builder["rejectDupKeys"] = true;
  builder["stackLimit"] = 32;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value root;
  std::string errors;
  const char* begin = reinterpret_cast<const char*>(body.data());
  const char* end = begin + body.size();
  try {
    if (!reader->parse(begin, end, &root, &errors)) {
      throw OtaError(400, "INVALID_REQUEST", "invalid JSON body: " + errors);
    }
  } catch (const OtaError&) {
    throw;
  } catch (const std::exception& e) {
    throw OtaError(400, "INVALID_REQUEST",
                   std::string("invalid JSON body: ") + e.what());
  }
  if (!root.isObject()) {
    throw OtaError(400, "INVALID_REQUEST", "JSON body must be an object");
  }
  return root;
}

template <class Body>
void require_content_type(const http::request<Body>& request,
                          const std::string& expected,
                          const char* code) {
  const beast::string_view value = request[http::field::content_type];
  if (value.empty()) {
    return;
  }
  if (!starts_with_ci(std::string(value), expected)) {
    throw OtaError(415, code,
                   "unsupported Content-Type; expected " + expected);
  }
}

uint64_t parse_upload_offset(const std::string& text) {
  uint64_t offset = 0;
  if (!parse_u64(text, &offset)) {
    throw OtaError(400, "INVALID_REQUEST",
                   "Upload-Offset must be a non-negative decimal integer");
  }
  return offset;
}

std::string read_header_value(const beast::string_view& value) {
  return std::string(value.data(), value.size());
}

}  // namespace

HttpServer::HttpServer(OtaService& service, const AppConfig& config)
    : service_(service),
      http_(config.http),
      max_chunk_bytes_(config.device.max_chunk_bytes),
      acceptor_(io_) {}

HttpServer::~HttpServer() { stop(); }

void HttpServer::start() {
  if (started_) {
    return;
  }
  tcp::endpoint endpoint;
  try {
    endpoint = tcp::endpoint(net::ip::make_address(http_.bind_address),
                             http_.port);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("invalid bind address: ") + e.what());
  }

  boost::system::error_code ec;
  acceptor_.open(endpoint.protocol(), ec);
  if (ec) {
    throw std::runtime_error("failed to open the listening socket: " +
                             ec.message());
  }
  acceptor_.set_option(net::socket_base::reuse_address(true), ec);
  if (ec) {
    throw std::runtime_error("failed to set SO_REUSEADDR: " + ec.message());
  }
  acceptor_.bind(endpoint, ec);
  if (ec) {
    throw std::runtime_error("failed to bind " + http_.bind_address + ":" +
                             std::to_string(http_.port) + ": " + ec.message());
  }
  acceptor_.listen(net::socket_base::max_listen_connections, ec);
  if (ec) {
    throw std::runtime_error("failed to listen: " + ec.message());
  }
  acceptor_.non_blocking(true, ec);
  if (ec) {
    throw std::runtime_error("failed to set the listener non-blocking: " +
                             ec.message());
  }

  started_ = true;
  accept_thread_ = std::thread([this]() { accept_loop(); });
  workers_.reserve(http_.threads);
  for (uint32_t i = 0; i < http_.threads; ++i) {
    workers_.emplace_back([this]() { worker_loop(); });
  }
  log_info("HTTP listening on " + http_.bind_address + ":" +
           std::to_string(bound_port()) + " with " +
           std::to_string(http_.threads) + " worker thread(s)");
}

void HttpServer::stop() {
  if (stopping_.exchange(true)) {
    return;
  }
  boost::system::error_code ec;
  acceptor_.close(ec);

  // Nothing should be left in the queue, but close it in case the workers have
  // already returned.
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    for (const SocketPtr& socket : queue_) {
      boost::system::error_code close_ec;
      socket->close(close_ec);
    }
    queue_.clear();
  }
  queue_cv_.notify_all();

  // shutdown(2), not close(), so we do not race with the worker that owns the
  // socket. A blocked read or write returns immediately.
  {
    std::lock_guard<std::mutex> lock(active_mutex_);
    for (const SocketPtr& socket : active_) {
      if (socket->is_open()) {
        ::shutdown(socket->native_handle(), SHUT_RDWR);
      }
    }
  }

  if (accept_thread_.joinable()) {
    accept_thread_.join();
  }
  for (std::thread& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  workers_.clear();
  log_info("HTTP server stopped");
}

uint16_t HttpServer::bound_port() const {
  boost::system::error_code ec;
  const tcp::endpoint endpoint = acceptor_.local_endpoint(ec);
  if (ec) {
    return http_.port;
  }
  return endpoint.port();
}

void HttpServer::configure_socket(Socket& socket) const {
  boost::system::error_code ec;
  socket.set_option(tcp::no_delay(true), ec);
  if (http_.idle_timeout_seconds == 0) {
    return;
  }
  timeval timeout{};
  timeout.tv_sec = static_cast<time_t>(http_.idle_timeout_seconds);
  timeout.tv_usec = 0;
  ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &timeout,
               sizeof(timeout));
  ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &timeout,
               sizeof(timeout));
}

void HttpServer::reject_overload(Socket& socket) const {
  // Do not let a slow client block the accept loop.
  timeval timeout{};
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &timeout,
               sizeof(timeout));
  const http::response<http::string_body> response = make_json_response(
      http::status::service_unavailable, 11, false,
      make_error_body("SERVER_BUSY", "too many queued connections"));
  boost::system::error_code ec;
  http::write(socket, response, ec);
  socket.shutdown(Socket::shutdown_both, ec);
  socket.close(ec);
}

void HttpServer::accept_loop() {
  while (!stopping_.load()) {
    SocketPtr socket = std::make_shared<Socket>(io_);
    boost::system::error_code ec;
    acceptor_.accept(*socket, ec);
    if (ec) {
      if (ec == net::error::would_block || ec == net::error::try_again) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        continue;
      }
      if (stopping_.load()) {
        break;
      }
      log_warn("accept failed: " + ec.message());
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    configure_socket(*socket);
    bool overloaded = false;
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      if (queue_.size() >= http_.max_queued_connections) {
        overloaded = true;
      } else {
        queue_.push_back(socket);
      }
    }
    if (overloaded) {
      reject_overload(*socket);
      continue;
    }
    queue_cv_.notify_one();
  }
}

void HttpServer::worker_loop() {
  for (;;) {
    SocketPtr socket;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this]() {
        return stopping_.load() || !queue_.empty();
      });
      if (stopping_.load()) {
        return;
      }
      socket = queue_.front();
      queue_.pop_front();
    }
    handle_connection(std::move(socket));
  }
}

void HttpServer::handle_connection(SocketPtr socket) {
  {
    std::lock_guard<std::mutex> lock(active_mutex_);
    if (stopping_.load()) {
      boost::system::error_code close_ec;
      socket->close(close_ec);
      return;
    }
    active_.insert(socket);
  }

  std::string remote = "unknown";
  {
    boost::system::error_code endpoint_ec;
    const tcp::endpoint endpoint = socket->remote_endpoint(endpoint_ec);
    if (!endpoint_ec) {
      remote = endpoint.address().to_string() + ":" +
               std::to_string(endpoint.port());
    }
  }

  beast::flat_buffer buffer;

  const auto send_error = [&](http::status status, unsigned version,
                              bool keep_alive, const std::string& code,
                              const std::string& message,
                              bool omit_body) -> bool {
    boost::system::error_code write_ec;
    if (omit_body) {
      http::response<http::empty_body> response{status, version};
      response.set(http::field::server, kServerName);
      response.set(http::field::content_type, "application/json; charset=utf-8");
      response.set("X-Error-Code", code);
      response.keep_alive(keep_alive);
      response.content_length(0);
      http::write(*socket, response, write_ec);
    } else {
      const http::response<http::string_body> response = make_json_response(
          status, version, keep_alive, make_error_body(code, message));
      http::write(*socket, response, write_ec);
    }
    if (write_ec) {
      log_debug("failed to write an error response to " + remote + ": " +
                write_ec.message());
      return false;
    }
    return true;
  };

  // Set when a response is sent without consuming a possibly in-flight body.
  // The connection then needs a bounded lingering close instead of a plain
  // close(), or the peer may see an RST and lose the error response.
  bool drain_before_close = false;

  while (!stopping_.load()) {
    http::request_parser<http::vector_body<uint8_t>> parser;
    parser.body_limit(http_.max_body_bytes);
    parser.header_limit(http_.max_header_bytes);
    drain_before_close = false;

    boost::system::error_code ec;
    http::read_header(*socket, buffer, parser, ec);
    if (ec == http::error::end_of_stream) {
      break;
    }
    if (ec) {
      if (is_timeout_error(ec)) {
        log_debug("connection " + remote + " idle timeout");
        break;
      }
      if (ec == http::error::header_limit) {
        drain_before_close = true;
        send_error(http::status::request_header_fields_too_large,
                   parser.get().version(), false, "HEADER_TOO_LARGE",
                   "request headers exceed max_header_bytes", false);
      } else {
        drain_before_close = true;
        send_error(http::status::bad_request, parser.get().version(), false,
                   "BAD_REQUEST", "malformed HTTP request", false);
      }
      break;
    }

    const unsigned version = parser.get().version();
    const bool keep_alive = parser.get().keep_alive();
    const Route route = parse_route(std::string(parser.get().target()));

    if (route.kind == RouteKind::None) {
      drain_before_close = true;
      send_error(http::status::not_found, version, false, "NOT_FOUND",
                 "unknown endpoint", false);
      break;
    }
    if (!method_allowed(route.kind, parser.get().method())) {
      drain_before_close = true;
      const Json::Value body = make_error_body("METHOD_NOT_ALLOWED",
                                               "method is not allowed here");
      http::response<http::string_body> response =
          make_json_response(http::status::method_not_allowed, version, false,
                             body);
      response.set(http::field::allow, allow_for(route.kind));
      http::write(*socket, response, ec);
      if (ec) {
        log_debug("failed to write 405 to " + remote + ": " + ec.message());
      }
      break;
    }

    const bool is_payload_upload =
        route.kind == RouteKind::PatchPayload &&
        parser.get().method() == http::verb::patch;
    uint64_t body_limit = http_.max_body_bytes;
    if (is_payload_upload) {
      body_limit = std::min<uint64_t>(body_limit, max_chunk_bytes_);
    }
    parser.body_limit(body_limit);

    const boost::optional<uint64_t> content_length = parser.content_length();
    const beast::string_view expect = parser.get()[http::field::expect];
    const bool has_expect_continue =
        !expect.empty() && equals_ci(expect, "100-continue");
    log_debug("request " + std::string(parser.get().method_string()) +
              " " + std::string(parser.get().target()) + " content_length=" +
              (content_length ? std::to_string(*content_length) : "none") +
              " chunked=" + (parser.chunked() ? "yes" : "no") +
              " body_limit=" + std::to_string(body_limit));
    if (content_length && *content_length > body_limit) {
      // With 100-continue the client is waiting and will not send the body.
      drain_before_close = !has_expect_continue;
      send_error(http::status::payload_too_large, version, false,
                 is_payload_upload ? "CHUNK_TOO_LARGE"
                                   : "REQUEST_BODY_TOO_LARGE",
                 is_payload_upload
                     ? "payload chunk exceeds device.max_chunk_bytes"
                     : "request body exceeds http.max_body_bytes",
                 false);
      break;
    }

    if (has_expect_continue) {
      static const char kContinue[] = "HTTP/1.1 100 Continue\r\n\r\n";
      net::write(*socket, net::buffer(kContinue, sizeof(kContinue) - 1), ec);
      if (ec) {
        log_debug("failed to write 100-continue to " + remote + ": " +
                  ec.message());
        break;
      }
    }

    http::read(*socket, buffer, parser, ec);
    if (ec) {
      log_debug("body read error for " + remote + ": " + ec.message() +
                " value=" + std::to_string(ec.value()) + " category=" +
                ec.category().name());
      if (is_timeout_error(ec)) {
        log_debug("connection " + remote + " timed out while reading the body");
        break;
      }
      if (ec == http::error::body_limit) {
        drain_before_close = true;
        send_error(http::status::payload_too_large, version, false,
                   is_payload_upload ? "CHUNK_TOO_LARGE"
                                     : "REQUEST_BODY_TOO_LARGE",
                   is_payload_upload
                       ? "payload chunk exceeds device.max_chunk_bytes"
                       : "request body exceeds the allowed size",
                   false);
      } else {
        drain_before_close = true;
        send_error(http::status::bad_request, version, false, "BAD_REQUEST",
                   "malformed request body", false);
      }
      break;
    }

    const http::request<http::vector_body<uint8_t>> request = parser.release();
    bool close_after = !keep_alive;

    try {
      if (route.kind == RouteKind::DeviceInfo) {
        const http::response<http::string_body> response = make_json_response(
            http::status::ok, version, keep_alive, service_.device_info());
        http::write(*socket, response, ec);
        log_debug(remote + " GET /ota/v1/device-info -> 200");
      } else if (route.kind == RouteKind::CreateSession) {
        require_content_type(request, "application/json",
                             "UNSUPPORTED_MEDIA_TYPE");
        const OtaService::CreateResult result =
            service_.create_or_resume_session(parse_json_body(request.body()));
        const http::response<http::string_body> response = make_json_response(
            result.created ? http::status::created : http::status::ok, version,
            keep_alive, result.body);
        http::write(*socket, response, ec);
        log_debug(remote + " POST /ota/v1/sessions -> " +
                  std::to_string(response.result_int()));
      } else if (route.kind == RouteKind::GetSession) {
        const http::response<http::string_body> response = make_json_response(
            http::status::ok, version, keep_alive,
            service_.get_session(route.session_id));
        http::write(*socket, response, ec);
        log_debug(remote + " GET /ota/v1/sessions/" + route.session_id +
                  " -> 200");
      } else if (route.kind == RouteKind::PatchPayload &&
                 request.method() == http::verb::head) {
        const Json::Value session = service_.get_session(route.session_id);
        http::response<http::empty_body> response{
            http::status::no_content, version};
        response.set(http::field::server, kServerName);
        response.set("Upload-Offset",
                     std::to_string(session["offset"].asUInt64()));
        response.set("Session-State", session["state"].asString());
        response.keep_alive(keep_alive);
        http::write(*socket, response, ec);
        log_debug(remote + " HEAD /ota/v1/sessions/" + route.session_id +
                  "/payload -> 204");
      } else if (route.kind == RouteKind::PatchPayload) {
        require_content_type(request, "application/octet-stream",
                             "UNSUPPORTED_MEDIA_TYPE");
        if (request.count("Upload-Offset") != 1) {
          throw OtaError(400, "INVALID_REQUEST",
                         "exactly one Upload-Offset header is required");
        }
        const uint64_t offset =
            parse_upload_offset(read_header_value(request["Upload-Offset"]));
        const uint64_t new_offset = service_.patch_payload(
            route.session_id, offset, request.body().data(),
            request.body().size());
        http::response<http::empty_body> response{
            http::status::no_content, version};
        response.set(http::field::server, kServerName);
        response.set("Upload-Offset", std::to_string(new_offset));
        response.keep_alive(keep_alive);
        http::write(*socket, response, ec);
        log_debug(remote + " PATCH /ota/v1/sessions/" + route.session_id +
                  "/payload " + std::to_string(offset) + "+" +
                  std::to_string(request.body().size()) + " -> 204 " +
                  std::to_string(new_offset));
      } else if (route.kind == RouteKind::Install) {
        require_content_type(request, "application/json",
                             "UNSUPPORTED_MEDIA_TYPE");
        const OtaService::InstallResult result = service_.install(
            route.session_id, parse_json_body(request.body()));
        const http::response<http::string_body> response =
            make_json_response(static_cast<http::status>(result.http_status),
                               version, keep_alive, result.body);
        http::write(*socket, response, ec);
        log_debug(remote + " POST /ota/v1/sessions/" + route.session_id +
                  "/install -> " + std::to_string(result.http_status));
      }
      if (ec) {
        log_debug("write to " + remote + " failed: " + ec.message());
        close_after = true;
      }
    } catch (const OtaError& e) {
      const bool ok = send_error(
          static_cast<http::status>(e.http_status()), version, keep_alive,
          e.code(), e.what(), request.method() == http::verb::head);
      close_after = !ok || !keep_alive;
      log_warn(remote + " " + std::string(request.method_string()) + " " +
               std::string(request.target()) + " -> " +
               std::to_string(e.http_status()) + " " + e.code());
    } catch (const std::exception& e) {
      log_error(remote + " " + std::string(request.method_string()) + " " +
                std::string(request.target()) + " failed: " + e.what());
      const bool ok = send_error(http::status::internal_server_error, version,
                                 keep_alive, "INTERNAL_ERROR",
                                 "internal server error",
                                 request.method() == http::verb::head);
      close_after = !ok || !keep_alive;
    }

    if (close_after || stopping_.load()) {
      break;
    }
  }

  if (drain_before_close && socket->is_open()) {
    // The response was already written without consuming the request body.
    // Half-close and discard a bounded amount of input so close() does not send
    // an RST that could discard the response at the peer.
    boost::system::error_code drain_ec;
    socket->shutdown(Socket::shutdown_send, drain_ec);
    timeval quick{};
    quick.tv_sec = 1;
    ::setsockopt(socket->native_handle(), SOL_SOCKET, SO_RCVTIMEO, &quick,
                 sizeof(quick));
    char scratch[4096];
    size_t drained = 0;
    constexpr size_t kMaxDrainBytes = 256 * 1024;
    while (drained < kMaxDrainBytes) {
      const ssize_t n =
          ::recv(socket->native_handle(), scratch, sizeof(scratch), 0);
      if (n <= 0) {
        break;
      }
      drained += static_cast<size_t>(n);
    }
  }

  {
    std::lock_guard<std::mutex> lock(active_mutex_);
    active_.erase(socket);
  }
  boost::system::error_code ec;
  socket->shutdown(Socket::shutdown_both, ec);
  socket->close(ec);
}

}  // namespace robot_ota
