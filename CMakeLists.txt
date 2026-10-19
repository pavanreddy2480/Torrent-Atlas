cmake_minimum_required(VERSION 3.16)
project(Torrent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(TORRENT_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Raft consensus for the tracker cluster: eBay NuRaft, which needs the
# header-only standalone asio for networking.
include(FetchContent)
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-30-2
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(asio)
set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include CACHE PATH "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  nuraft
  GIT_REPOSITORY https://github.com/eBay/NuRaft.git
  GIT_TAG 0b01b18
)
FetchContent_MakeAvailable(nuraft)

add_library(torrent_raft INTERFACE)
target_include_directories(torrent_raft SYSTEM INTERFACE
  ${nuraft_SOURCE_DIR}/include
  ${nuraft_SOURCE_DIR}/include/libnuraft
  ${ASIO_INCLUDE_DIR})
target_compile_definitions(torrent_raft INTERFACE ASIO_STANDALONE)
target_link_libraries(torrent_raft INTERFACE
  NuRaft::static_lib OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

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
  common/client_config.cpp
  common/cluster_config.cpp
  common/cluster_keys.cpp
  common/crypto.cpp
  common/encoding.cpp
  common/file_metadata.cpp
  common/net.cpp
  common/secure_channel.cpp
  common/tcp_server.cpp
)
target_link_libraries(torrent_common PUBLIC OpenSSL::Crypto Threads::Threads)
torrent_warnings(torrent_common)

# Everything in the tracker except main(), so tests can use it.
add_library(tracker_core STATIC
  tracker/log_command.cpp
  tracker/password.cpp
  tracker/raft_node.cpp
  tracker/raft_storage.cpp
  tracker/state_machine.cpp
  tracker/state_snapshot.cpp
  tracker/storage_io.cpp
  tracker/tracker_state.cpp
)
target_link_libraries(tracker_core PUBLIC torrent_common torrent_raft)
torrent_warnings(tracker_core)

# Everything in the client except main().
add_library(client_core STATIC
  client/client.cpp
  client/command_line.cpp
  client/download.cpp
  client/download_manager.cpp
  client/peer_client.cpp
  client/peer_protocol.cpp
  client/peer_server.cpp
  client/peer_stats.cpp
  client/piece_file.cpp
  client/resume_manifest.cpp
  client/shared_files.cpp
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
torrent_test(tracker_integration_tests torrent_common $<TARGET_FILE:tracker>)
torrent_test(client_integration_tests torrent_common $<TARGET_FILE:tracker> $<TARGET_FILE:client>)
torrent_test(peer_rejection_test torrent_common $<TARGET_FILE:client>)
