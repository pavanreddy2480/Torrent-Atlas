cmake_minimum_required(VERSION 3.16)
project(Torrent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(TORRENT_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

function(torrent_warnings target)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  if(TORRENT_ENABLE_SANITIZERS)
    target_compile_options(${target} PRIVATE
      -fsanitize=address,undefined
      -fno-omit-frame-pointer
    )
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

add_executable(client
  client/client.cpp
  client/command_utils.cpp
  client/download_storage.cpp
  client/network_utils.cpp
  client/telemetry.cpp
)
target_link_libraries(client PRIVATE
  Threads::Threads
  OpenSSL::Crypto
)
torrent_warnings(client)

add_executable(tracker tracker/tracker.cpp)
target_link_libraries(tracker PRIVATE Threads::Threads OpenSSL::Crypto)
torrent_warnings(tracker)

add_executable(tracker_lb tracker/tracker_lb.cpp)
target_link_libraries(tracker_lb PRIVATE Threads::Threads OpenSSL::Crypto)
torrent_warnings(tracker_lb)

add_executable(torrent_keygen tools/keygen.cpp)
target_link_libraries(torrent_keygen PRIVATE OpenSSL::Crypto)
torrent_warnings(torrent_keygen)

add_executable(security_tests tests/security_tests.cpp)
target_link_libraries(security_tests PRIVATE
  Threads::Threads
  OpenSSL::Crypto
)
target_compile_options(security_tests PRIVATE -UNDEBUG)
torrent_warnings(security_tests)

add_executable(peer_rejection_test tests/peer_rejection_test.cpp)
target_link_libraries(peer_rejection_test PRIVATE Threads::Threads OpenSSL::Crypto)
target_compile_options(peer_rejection_test PRIVATE -UNDEBUG)
torrent_warnings(peer_rejection_test)

add_executable(tracker_state_tests tests/tracker_state_tests.cpp)
target_link_libraries(tracker_state_tests PRIVATE Threads::Threads OpenSSL::Crypto)
target_compile_options(tracker_state_tests PRIVATE -UNDEBUG)
torrent_warnings(tracker_state_tests)

add_executable(command_parser_tests tests/command_parser_tests.cpp)
target_compile_options(command_parser_tests PRIVATE -UNDEBUG)
torrent_warnings(command_parser_tests)

add_executable(protocol_tests tests/protocol_tests.cpp)
target_link_libraries(protocol_tests PRIVATE Threads::Threads)
target_compile_options(protocol_tests PRIVATE -UNDEBUG)
torrent_warnings(protocol_tests)

add_executable(download_storage_tests
  tests/download_storage_tests.cpp client/download_storage.cpp)
target_link_libraries(download_storage_tests PRIVATE Threads::Threads)
target_compile_options(download_storage_tests PRIVATE -UNDEBUG)
torrent_warnings(download_storage_tests)

add_executable(tracker_integration_tests tests/tracker_integration_tests.cpp)
target_link_libraries(tracker_integration_tests PRIVATE Threads::Threads OpenSSL::Crypto)
target_compile_options(tracker_integration_tests PRIVATE -UNDEBUG)
torrent_warnings(tracker_integration_tests)

add_executable(tracker_lb_integration_tests tests/tracker_lb_integration_tests.cpp)
target_link_libraries(tracker_lb_integration_tests PRIVATE Threads::Threads OpenSSL::Crypto)
target_compile_options(tracker_lb_integration_tests PRIVATE -UNDEBUG)
torrent_warnings(tracker_lb_integration_tests)

add_executable(client_integration_tests tests/client_integration_tests.cpp)
target_link_libraries(client_integration_tests PRIVATE Threads::Threads OpenSSL::Crypto)
target_compile_options(client_integration_tests PRIVATE -UNDEBUG)
torrent_warnings(client_integration_tests)

enable_testing()
add_test(NAME security_tests COMMAND security_tests)
add_test(NAME tracker_state_tests COMMAND tracker_state_tests)
add_test(NAME command_parser_tests COMMAND command_parser_tests)
add_test(NAME protocol_tests COMMAND protocol_tests)
add_test(NAME download_storage_tests COMMAND download_storage_tests)
add_test(
  NAME tracker_integration_tests
  COMMAND tracker_integration_tests $<TARGET_FILE:tracker>
)
set_tests_properties(
  tracker_integration_tests
  PROPERTIES TIMEOUT 20 SKIP_RETURN_CODE 77
)
add_test(
  NAME tracker_lb_integration_tests
  COMMAND tracker_lb_integration_tests $<TARGET_FILE:tracker> $<TARGET_FILE:tracker_lb>
)
set_tests_properties(
  tracker_lb_integration_tests
  PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77
)
add_test(
  NAME client_integration_tests
  COMMAND client_integration_tests $<TARGET_FILE:tracker>
          $<TARGET_FILE:tracker_lb> $<TARGET_FILE:client>
)
set_tests_properties(
  client_integration_tests
  PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77
)
add_test(
  NAME peer_rejection_test
  COMMAND peer_rejection_test $<TARGET_FILE:client>
)
set_tests_properties(
  peer_rejection_test
  PROPERTIES TIMEOUT 20 SKIP_RETURN_CODE 77
)
