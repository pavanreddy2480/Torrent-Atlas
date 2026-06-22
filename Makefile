CXX      = g++
CXXFLAGS = -Wall -Wextra -O2 -pthread -std=c++17
OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   = $(shell pkg-config --libs openssl 2>/dev/null || echo -lcrypto)
BIN_DIR = bin

# directories
CLIENT_DIR  = client
TRACKER_DIR = tracker

# targets
CLIENT   = $(BIN_DIR)/client
TRACKER  = $(BIN_DIR)/tracker
TRACKER1 = $(BIN_DIR)/tracker1
TRACKER2 = $(BIN_DIR)/tracker2
SECURITY_TEST = $(BIN_DIR)/tests/security_tests
PEER_REJECTION_TEST = $(BIN_DIR)/tests/peer_rejection_test
TRACKER_STATE_TEST = $(BIN_DIR)/tests/tracker_state_tests
COMMAND_PARSER_TEST = $(BIN_DIR)/tests/command_parser_tests

# default target
all: $(CLIENT) $(TRACKER) $(TRACKER1) $(TRACKER2)

# ----- build rules -----
$(CLIENT): $(CLIENT_DIR)/client.cpp $(CLIENT_DIR)/command_utils.cpp $(CLIENT_DIR)/command_utils.hpp $(CLIENT_DIR)/download_storage.cpp $(CLIENT_DIR)/download_storage.hpp $(CLIENT_DIR)/network_utils.cpp $(CLIENT_DIR)/network_utils.hpp $(CLIENT_DIR)/telemetry.cpp $(CLIENT_DIR)/telemetry.hpp $(CLIENT_DIR)/tui_model.cpp $(CLIENT_DIR)/tui_model.hpp $(CLIENT_DIR)/client_types.hpp $(CLIENT_DIR)/tui_theme.hpp common/protocol.hpp common/sha1.hpp common/secure_crypto.hpp common/peer_crypto.hpp common/peer_crypto.cpp common/command_parser.hpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $@ $(CLIENT_DIR)/client.cpp $(CLIENT_DIR)/command_utils.cpp $(CLIENT_DIR)/download_storage.cpp $(CLIENT_DIR)/network_utils.cpp $(CLIENT_DIR)/telemetry.cpp $(CLIENT_DIR)/tui_model.cpp common/peer_crypto.cpp $(OPENSSL_LIBS)

$(TRACKER): $(TRACKER_DIR)/tracker.cpp $(TRACKER_DIR)/tracker_common.hpp common/protocol.hpp common/secure_crypto.hpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LIBS)

$(TRACKER1): $(TRACKER_DIR)/tracker1.cpp $(TRACKER_DIR)/tracker_common.hpp common/protocol.hpp common/secure_crypto.hpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LIBS)

$(TRACKER2): $(TRACKER_DIR)/tracker2.cpp $(TRACKER_DIR)/tracker_common.hpp common/protocol.hpp common/secure_crypto.hpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LIBS)

clean:
	rm -rf $(BIN_DIR) client/client tracker/tracker tracker/tracker1 tracker/tracker2 \
		tests/security_tests tests/peer_rejection_test tests/tracker_state_tests \
		tests/command_parser_tests

security-test: tests/security_tests.cpp common/secure_crypto.hpp common/peer_crypto.hpp common/peer_crypto.cpp common/protocol.hpp
	@mkdir -p $(dir $(SECURITY_TEST))
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $(SECURITY_TEST) $< common/peer_crypto.cpp $(OPENSSL_LIBS)
	./$(SECURITY_TEST)

peer-rejection-test: tests/peer_rejection_test.cpp common/protocol.hpp
	@mkdir -p $(dir $(PEER_REJECTION_TEST))
	$(CXX) $(CXXFLAGS) -o $(PEER_REJECTION_TEST) $<
	./$(PEER_REJECTION_TEST) $(PORT)

tracker-state-test: tests/tracker_state_tests.cpp tracker/tracker_common.hpp common/protocol.hpp common/secure_crypto.hpp
	@mkdir -p $(dir $(TRACKER_STATE_TEST))
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $(TRACKER_STATE_TEST) $< $(OPENSSL_LIBS)
	./$(TRACKER_STATE_TEST)

command-parser-test: tests/command_parser_tests.cpp common/command_parser.hpp
	@mkdir -p $(dir $(COMMAND_PARSER_TEST))
	$(CXX) $(CXXFLAGS) -o $(COMMAND_PARSER_TEST) $<
	./$(COMMAND_PARSER_TEST)
