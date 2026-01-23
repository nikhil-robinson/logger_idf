# Blackbox Linux Examples Makefile
#
# Build all examples:  make all
# Build specific:      make basic_logging
# Clean:               make clean
# Run test:            make test

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -lm

# Paths relative to this directory
ROOT_DIR = ../..
INCLUDE_DIRS = -I$(ROOT_DIR) -I$(ROOT_DIR)/core -I$(ROOT_DIR)/hal -I$(ROOT_DIR)/include
CORE_SRC = $(ROOT_DIR)/core/blackbox_core.c
HAL_SRC = $(ROOT_DIR)/hal/blackbox_hal_posix.c

# Common sources for all examples
COMMON_SRCS = $(CORE_SRC) $(HAL_SRC)

# Example targets
EXAMPLES = basic_logging flight_data single_threaded multi_format ardupilot_pid

.PHONY: all clean test help

all: $(EXAMPLES)

basic_logging: basic_logging.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LDFLAGS)

flight_data: flight_data.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LDFLAGS)

single_threaded: single_threaded.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LDFLAGS)

multi_format: multi_format.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LDFLAGS)

ardupilot_pid: ardupilot_pid.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXAMPLES)
	rm -rf /tmp/blackbox_logs /tmp/blackbox_flight /tmp/blackbox_polling /tmp/blackbox_formats /tmp/blackbox_ardupilot

test: basic_logging
	@echo "Running basic_logging test (5 seconds)..."
	@mkdir -p /tmp/blackbox_logs
	@timeout 5 ./basic_logging || true
	@echo "\nTest complete. Check /tmp/blackbox_logs for output."

help:
	@echo "Blackbox Linux Examples"
	@echo ""
	@echo "Targets:"
	@echo "  all             Build all examples"
	@echo "  basic_logging   Basic text logging (like spiffs_example)"
	@echo "  flight_data     Structured flight data logging"
	@echo "  single_threaded Polling mode demo"
	@echo "  multi_format    Compare BBOX/ULog/ArduPilot formats"
	@echo "  clean           Remove binaries and log files"
	@echo "  test            Quick test run"
	@echo ""
	@echo "Usage:"
	@echo "  make all"
	@echo "  ./basic_logging"
	@echo "  ./flight_data --format ulog --duration 10"
	@echo "  ./single_threaded"
	@echo "  ./multi_format"
