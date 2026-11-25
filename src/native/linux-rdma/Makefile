BUILD_DIR ?= bin
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS = -lrdmacm -libverbs

.PHONY: all test
all: $(BUILD_DIR)/libTedd.SMB3.LinuxRdma.so

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR)/libTedd.SMB3.LinuxRdma.so: smbdirect.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 -fPIC -shared $(LDFLAGS) -o "$@" $< $(LDLIBS)

$(BUILD_DIR)/queue-tests: ../../../tests/native/linux-rdma/queue-tests.c smbdirect.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(LDFLAGS) -o "$@" $< $(LDLIBS)

test: all $(BUILD_DIR)/queue-tests
	"$(BUILD_DIR)/queue-tests"
