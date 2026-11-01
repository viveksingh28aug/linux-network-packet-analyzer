# Linux Raw Socket Network Packet Analyzer
# Optimized for Cisco Silicon One Software Systems Engineering

CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -O3 -g -I include -I src/headers -I src/globals -D_GNU_SOURCE -pipe
LDFLAGS ?= 

# Source modules
CORE_SRCS = src/core/capture.c \
            src/parser/parser.c \
            src/parser/checksum.c \
            src/filter/filter.c \
            src/analytics/analytics.c \
            src/printer/printer.c \
            src/pcap/pcap.c

CORE_OBJS = $(CORE_SRCS:.c=.o)

MAIN_SRC = src/main/sniffer.c
MAIN_OBJ = $(MAIN_SRC:.c=.o)

TEST_SRC = tests/test_runner.c
TEST_OBJ = $(TEST_SRC:.c=.o)

BENCH_SRC = benchmarks/benchmark.c
BENCH_OBJ = $(BENCH_SRC:.c=.o)

TARGET = sniffer
TEST_TARGET = test_runner
BENCH_TARGET = benchmark

TEST_SAN_TARGET = test_runner_sanitized

.PHONY: all clean test check run-benchmark test-sanitizers help

all: $(TARGET) $(TEST_TARGET) $(BENCH_TARGET)

$(TARGET): $(CORE_OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_TARGET): $(CORE_OBJS) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BENCH_TARGET): $(CORE_OBJS) $(BENCH_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_SAN_TARGET): $(CORE_SRCS) $(TEST_SRC)
	$(CC) -Wall -Wextra -Werror -O2 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -I include -I src/headers -I src/globals -D_GNU_SOURCE -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run unit tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

check: test

# Run unit tests with AddressSanitizer and UndefinedBehaviorSanitizer
test-sanitizers: $(TEST_SAN_TARGET)
	./$(TEST_SAN_TARGET)

# Run performance benchmark
run-benchmark: $(BENCH_TARGET)
	./$(BENCH_TARGET)

clean:
	rm -f $(CORE_OBJS) $(MAIN_OBJ) $(TEST_OBJ) $(BENCH_OBJ)
	rm -f $(TARGET) $(TEST_TARGET) $(BENCH_TARGET) $(TEST_SAN_TARGET) test_runner_ubsan sniff.log

help:
	@echo "Available build targets:"
	@echo "  make                - Build sniffer, test_runner, and benchmark"
	@echo "  make sniffer        - Build main sniffer executable"
	@echo "  make test           - Build and execute unit tests (no root needed)"
	@echo "  make run-benchmark  - Build and execute parser throughput benchmark"
	@echo "  make clean          - Remove build artifacts and temporary binaries"
