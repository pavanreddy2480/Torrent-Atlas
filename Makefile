BUILD_DIR ?= build
SANITIZE_DIR ?= build-sanitize
CMAKE_FLAGS ?=

.PHONY: all build test sanitize clean

all: build

build:
	cmake -S . -B $(BUILD_DIR) $(CMAKE_FLAGS)
	cmake --build $(BUILD_DIR) -j

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

sanitize:
	cmake -S . -B $(SANITIZE_DIR) -DTORRENT_ENABLE_SANITIZERS=ON
	cmake --build $(SANITIZE_DIR) -j
	ctest --test-dir $(SANITIZE_DIR) --output-on-failure

clean:
	cmake -E remove_directory $(BUILD_DIR)
	cmake -E remove_directory $(SANITIZE_DIR)
