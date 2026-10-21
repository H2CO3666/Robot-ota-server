cmake_minimum_required(VERSION 3.13)
project(robot_ota_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

find_package(OpenSSL REQUIRED)
find_package(Boost 1.71 REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

# Ubuntu's libjsoncpp-dev does not ship a CMake config file.
find_path(JSONCPP_INCLUDE_DIR NAMES json/json.h PATH_SUFFIXES jsoncpp REQUIRED)
find_library(JSONCPP_LIBRARY NAMES jsoncpp REQUIRED)

add_executable(robot-ota-server
  src/main.cpp
  src/config.cpp
  src/util.cpp
  src/jcs.cpp
  src/crypto.cpp
  src/se_device_key.cpp
  src/manifest.cpp
  src/storage.cpp
  src/ota_engine.cpp
  src/ota_service.cpp
  src/http_server.cpp
)

target_include_directories(robot-ota-server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${JSONCPP_INCLUDE_DIR}
)

target_link_libraries(robot-ota-server PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  Boost::system
  Threads::Threads
  ${JSONCPP_LIBRARY}
  ${CMAKE_DL_LIBS}
)

target_compile_options(robot-ota-server PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wshadow
  -Wconversion
  -Wno-sign-conversion
  -fstack-protector-strong
)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-D_FORTIFY_SOURCE=2" HAVE_FORTIFY)
if(HAVE_FORTIFY)
  target_compile_definitions(robot-ota-server PRIVATE _FORTIFY_SOURCE=2)
endif()

# ---------------------------------------------------------------------------
# Unit tests (optional)
# ---------------------------------------------------------------------------
option(ROBOT_OTA_BUILD_TESTS "Build unit tests" ON)
if(ROBOT_OTA_BUILD_TESTS)
  enable_testing()

  add_executable(robot-ota-unit-tests
    tests/unit_tests.cpp
    src/jcs.cpp
    src/crypto.cpp
    src/util.cpp
    src/manifest.cpp
  )
  target_include_directories(robot-ota-unit-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${JSONCPP_INCLUDE_DIR}
  )
  target_link_libraries(robot-ota-unit-tests PRIVATE
    OpenSSL::Crypto
    Threads::Threads
    ${JSONCPP_LIBRARY}
    ${CMAKE_DL_LIBS}
  )
  target_compile_options(robot-ota-unit-tests PRIVATE -Wall -Wextra)
  add_test(NAME unit_tests COMMAND robot-ota-unit-tests)

  # End-to-end protocol tests. They generate a throwaway PKI and data directory
  # under a temporary path and need only the Python standard library plus
  # `cryptography`.
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME integration_tests
      COMMAND Python3::Interpreter
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.py
              --server $<TARGET_FILE:robot-ota-server>)
    set_tests_properties(integration_tests PROPERTIES TIMEOUT 600)
  endif()
endif()
