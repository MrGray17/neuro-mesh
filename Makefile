# ============================================================
# NEURO-MESH : UNIFIED BUILD SYSTEM (V6.0)
# ============================================================
CXX = clang++
CXXFLAGS = -std=c++20 -Wall -Wextra -O3
BPF_CC = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu

SSL_LIBS = -lssl -lcrypto -lpthread
BPF_LIBS = -lbpf -lelf -lz -lpthread

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
BPF_SRC = $(SRC_DIR)/bpf/sensor.bpf.c
AGENT_TARGET = $(BIN_DIR)/neuro_agent

all: directories $(AGENT_TARGET)

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(OBJ_DIR)/sensor.bpf.o: $(BPF_SRC)
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

$(SRC_DIR)/sensor.skel.h: $(OBJ_DIR)/sensor.bpf.o
	bpftool gen skeleton $< > $@

$(AGENT_TARGET): $(SRC_DIR)/main.cpp $(SRC_DIR)/SovereignCell.cpp $(SRC_DIR)/InferenceEngine.cpp $(SRC_DIR)/SystemJailer.cpp $(SRC_DIR)/MeshNode.cpp $(SRC_DIR)/AuditLogger.cpp $(SRC_DIR)/sensor.skel.h
	$(CXX) $(CXXFLAGS) $(filter %.cpp,$^) -o $@ $(BPF_LIBS) $(SSL_LIBS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(SRC_DIR)/sensor.skel.h

.PHONY: all directories clean
