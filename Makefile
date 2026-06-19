CXX      = g++
CXXFLAGS = -Wall -Wextra -O2 -pthread -std=c++17
GMP_CFLAGS = $(shell pkg-config --cflags gmp 2>/dev/null)
GMP_LIBS   = $(shell pkg-config --libs gmp 2>/dev/null || echo -lgmp)

# directories
CLIENT_DIR  = client
TRACKER_DIR = tracker

# targets
CLIENT   = $(CLIENT_DIR)/client
TRACKER  = $(TRACKER_DIR)/tracker
TRACKER1 = $(TRACKER_DIR)/tracker1
TRACKER2 = $(TRACKER_DIR)/tracker2
SECURITY_TEST = tests/security_tests
PEER_REJECTION_TEST = tests/peer_rejection_test

# default target
all: $(CLIENT) $(TRACKER) $(TRACKER1) $(TRACKER2)

# ----- build rules -----
$(CLIENT): $(CLIENT_DIR)/client.cpp common/protocol.hpp common/sha1.hpp common/secure_crypto.hpp common/elgamal.hpp
	$(CXX) $(CXXFLAGS) $(GMP_CFLAGS) -o $@ $< $(GMP_LIBS)

$(TRACKER): $(TRACKER_DIR)/tracker.cpp $(TRACKER_DIR)/tracker_common.hpp common/protocol.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

$(TRACKER1): $(TRACKER_DIR)/tracker1.cpp $(TRACKER_DIR)/tracker_common.hpp common/protocol.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

$(TRACKER2): $(TRACKER_DIR)/tracker2.cpp $(TRACKER_DIR)/tracker_common.hpp common/protocol.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(CLIENT) $(TRACKER) $(TRACKER1) $(TRACKER2) $(SECURITY_TEST) $(PEER_REJECTION_TEST)

security-test: tests/security_tests.cpp common/secure_crypto.hpp common/elgamal.hpp common/protocol.hpp
	$(CXX) $(CXXFLAGS) $(GMP_CFLAGS) -o $(SECURITY_TEST) $< $(GMP_LIBS)
	./$(SECURITY_TEST)

peer-rejection-test: tests/peer_rejection_test.cpp common/protocol.hpp
	$(CXX) $(CXXFLAGS) -o $(PEER_REJECTION_TEST) $<
	./$(PEER_REJECTION_TEST) $(PORT)
