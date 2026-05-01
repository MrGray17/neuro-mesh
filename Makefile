# ==============================================================================
# NEURO-MESH : SOVEREIGN BUILD SYSTEM (UNIFIED PIPELINE)
# ==============================================================================

CXX = clang++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -O3
BPF_CC = clang

# Explicitly link host architecture headers for eBPF networking structs
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu

# Libraries
SSL_LIBS = -lssl -lcrypto -lpthread
BPF_LIBS = -lbpf -lelf -lz -lpthread

# Paths
SRC_DIR = src
BPF_SRC = $(SRC_DIR)/bpf/sensor.bpf.c
OBJ_DIR = obj
BIN_DIR = bin

# Targets
AGENT_TARGET = $(BIN_DIR)/neuro_agent
CLIENT_TARGET = client
LISTENER_TARGET = listener

all: directories $(AGENT_TARGET) $(CLIENT_TARGET) $(LISTENER_TARGET)

directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# 1. Compile BPF code to object file
$(OBJ_DIR)/sensor.bpf.o: $(BPF_SRC)
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

# 2. Generate C Header Skeleton from BPF object
$(SRC_DIR)/sensor.skel.h: $(OBJ_DIR)/sensor.bpf.o
	bpftool gen skeleton $< > $@

# 3. Compile Core Sovereign Agent
$(AGENT_TARGET): $(SRC_DIR)/main.cpp $(SRC_DIR)/SovereignCell.cpp $(SRC_DIR)/InferenceEngine.cpp $(SRC_DIR)/SystemJailer.cpp $(SRC_DIR)/MeshNode.cpp $(SRC_DIR)/AuditLogger.cpp $(SRC_DIR)/sensor.skel.h
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/main.cpp $(SRC_DIR)/SovereignCell.cpp $(SRC_DIR)/InferenceEngine.cpp $(SRC_DIR)/SystemJailer.cpp $(SRC_DIR)/MeshNode.cpp $(SRC_DIR)/AuditLogger.cpp -o $@ $(BPF_LIBS)

# 4. Compile P2P Mesh Client
$(CLIENT_TARGET): client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o $@ $(SSL_LIBS)

# 5. Compile C2 Listener
$(LISTENER_TARGET): listener.cpp
	$(CXX) $(CXXFLAGS) listener.cpp -o $@ $(SSL_LIBS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(SRC_DIR)/sensor.skel.h $(CLIENT_TARGET) $(LISTENER_TARGET)

.PHONY: all directories clean
