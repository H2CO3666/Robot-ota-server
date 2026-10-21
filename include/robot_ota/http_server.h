#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "robot_ota/config.h"
#include "robot_ota/ota_service.h"

namespace robot_ota {

// Small HTTP/1.1 server for the robot-side offline OTA API.
//
// Design notes:
//   * One accept thread plus a fixed worker pool. Each connection is handled
//     synchronously by one worker, which keeps the handler code linear and
//     makes the "fsync before ACK" guarantee easy to see.
//   * Request bodies are bounded; the payload chunk limit is applied before
//     the body is read. Chunked request bodies are supported.
//   * Expect: 100-continue is answered explicitly before reading the body.
//   * The listener is non-blocking so stop() does not depend on a signal or a
//     timeout to interrupt accept(). On stop, active sockets are shutdown(2)
//     to unblock workers.
class HttpServer {
 public:
  HttpServer(OtaService& service, const AppConfig& config);
  ~HttpServer();
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  void start();
  void stop();

  // Actual bound port (useful when the configured port is 0).
  uint16_t bound_port() const;

 private:
  using Socket = boost::asio::ip::tcp::socket;
  using SocketPtr = std::shared_ptr<Socket>;

  void accept_loop();
  void worker_loop();
  void handle_connection(SocketPtr socket);

  void reject_overload(Socket& socket) const;
  void configure_socket(Socket& socket) const;

  OtaService& service_;
  HttpConfig http_;
  uint32_t max_chunk_bytes_ = 0;

  boost::asio::io_context io_;
  boost::asio::ip::tcp::acceptor acceptor_;

  std::thread accept_thread_;
  std::vector<std::thread> workers_;

  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::deque<SocketPtr> queue_;

  mutable std::mutex active_mutex_;
  std::unordered_set<SocketPtr> active_;

  std::atomic<bool> stopping_{false};
  bool started_ = false;
};

}  // namespace robot_ota
