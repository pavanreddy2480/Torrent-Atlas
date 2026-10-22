cmake_minimum_required(VERSION 3.16)
project(Torrent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# build/compile_commands.json tells clangd (VS Code) the include paths and flags.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
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

# Code shared by every program: networking, crypto, configuration and keys.
add_library(torrent_common STATIC
  common/config/client_config.cpp
  common/config/tracker_identity.cpp
  common/crypto/crypto.cpp
  common/encoding.cpp
  common/file_metadata.cpp
  common/peer_ticket.cpp
  common/net/net.cpp
  common/net/secure_channel.cpp
  common/net/tcp_server.cpp
)
# Includes are written from the repository root, e.g. "common/net/net.hpp".
target_include_directories(torrent_common PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(torrent_common PUBLIC OpenSSL::Crypto Threads::Threads)
torrent_warnings(torrent_common)

# Everything in the tracker except main(), so tests can use it.
add_library(tracker_core STATIC
  tracker/state/password.cpp
  tracker/state/state_snapshot.cpp
  tracker/state/tracker_state.cpp
  tracker/state_file.cpp
  tracker/tracker_service.cpp
)
target_link_libraries(tracker_core PUBLIC torrent_common)
torrent_warnings(tracker_core)

# Everything in the client except main().
add_library(client_core STATIC
  client/client.cpp
  client/command_line.cpp
  client/download/download.cpp
  client/download/download_manager.cpp
  client/download/resume_manifest.cpp
  client/peer/peer_client.cpp
  client/peer/peer_protocol.cpp
  client/peer/peer_server.cpp
  client/peer/peer_stats.cpp
  client/storage/piece_file.cpp
  client/storage/shared_files.cpp
  client/tracker_client.cpp
)
target_link_libraries(client_core PUBLIC torrent_common)
torrent_warnings(client_core)

add_executable(tracker tracker/main.cpp)
target_link_libraries(tracker PRIVATE tracker_core)
torrent_warnings(tracker)

add_executable(client client/main.cpp)
target_link_libraries(client PRIVATE client_core)
torrent_warnings(client)

add_executable(torrent_keygen tools/keygen.cpp)
target_link_libraries(torrent_keygen PRIVATE torrent_common)
torrent_warnings(torrent_keygen)

# Tests. Each takes the binaries it starts as arguments; exit code 77 means
# "skipped" (no local sockets).
enable_testing()
function(torrent_test name library)
  add_executable(${name} tests/${name}.cpp)
  target_link_libraries(${name} PRIVATE ${library})
  target_compile_options(${name} PRIVATE -UNDEBUG)
  torrent_warnings(${name})
  add_test(NAME ${name} COMMAND ${name} ${ARGN})
  set_tests_properties(${name} PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
endfunction()

torrent_test(net_tests torrent_common)
torrent_test(security_tests torrent_common)
torrent_test(command_line_tests client_core)
torrent_test(resume_tests client_core)
torrent_test(tracker_state_tests tracker_core)
torrent_test(peer_access_tests client_core)
torrent_test(tracker_integration_tests torrent_common $<TARGET_FILE:tracker>)
torrent_test(client_integration_tests client_core $<TARGET_FILE:tracker> $<TARGET_FILE:client>)
torrent_test(peer_rejection_test torrent_common $<TARGET_FILE:client>)
