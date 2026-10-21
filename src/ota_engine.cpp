#include "robot_ota/ota_engine.h"

#include <stdexcept>

namespace robot_ota {
namespace {

class DisabledOtaEngine final : public IOtaEngine {
 public:
  bool enabled() const override { return false; }

  InstallStartResult start(const InstallRequest&) override {
    return InstallStartResult::Unsupported;
  }

  InstallStatus query(const InstallRequest&) override {
    InstallStatus status;
    status.state = InstallStatus::State::Unknown;
    status.error_code = "INSTALL_NOT_SUPPORTED";
    status.message = "install execution is not implemented in this build";
    return status;
  }
};

}  // namespace

std::unique_ptr<IOtaEngine> make_ota_engine(const InstallConfig& config) {
  if (config.engine == "disabled") {
    return std::make_unique<DisabledOtaEngine>();
  }
  throw std::runtime_error("unsupported install.engine: " + config.engine);
}

}  // namespace robot_ota
