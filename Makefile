# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
else
    DETECTED_OS := $(shell uname -s)
endif

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinc -fPIC
DEBUG_FLAGS = -g -O0 -DDEBUG

# Platform-specific settings
ifeq ($(DETECTED_OS),Windows)
    # Windows settings
    LIB = libec.dll
    EXAMPLE = main.exe
    RM = del /Q
    RMDIR = rmdir /S /Q
    MKDIR = mkdir
    CP = copy
    LDFLAGS = -shared -lmodplus -lbcrypt
    INSTALL_DIR = C:\Windows\System32
    PATH_SEP = \\
    CFLAGS += -DWINDOWS=1 -DLINUX=0
else ifeq ($(DETECTED_OS),Linux)
    # Linux settings
    LIB = libec.so
    EXAMPLE = main
    RM = rm -f
    RMDIR = rm -rf
    MKDIR = mkdir -p
    CP = sudo cp
    LDFLAGS = -shared -lmodplus
    INSTALL_DIR = /usr/local/lib
    PATH_SEP = /
    CFLAGS += -DLINUX=1 -DWINDOWS=0
else ifeq ($(DETECTED_OS),Darwin)
    # macOS settings
    LIB = libec.dylib
    EXAMPLE = main
    RM = rm -f
    RMDIR = rm -rf
    MKDIR = mkdir -p
    CP = sudo cp
    LDFLAGS = -shared -lmodplus
    INSTALL_DIR = /usr/local/lib
    PATH_SEP = /
    CFLAGS += -DLINUX=1 -DWINDOWS=0
endif

# Directories
SRC_DIR = src
OBJ_DIR = build
INC_DIR = inc

# Source and object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Example files
EXAMPLE_SRC := examples/main.c

# Phony targets
.PHONY: all clean install uninstall debug help

# Default target
all: $(LIB) $(EXAMPLE)

# Build shared library
$(LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Compile object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build example executable
$(EXAMPLE): $(EXAMPLE_SRC) $(LIB)
	$(CC) -Wall -Wextra -Iinc -L. -o $@ $< -lec -lmodplus $(DEBUG_FLAGS)

# Create build directory
$(OBJ_DIR):
	$(MKDIR) $(OBJ_DIR)

# Install library to system
install: $(LIB)
ifeq ($(DETECTED_OS),Windows)
	$(CP) $(LIB) $(INSTALL_DIR)
	@echo Library installed to $(INSTALL_DIR)
else
	$(CP) $(LIB) $(INSTALL_DIR)
	@echo Library installed to $(INSTALL_DIR)
	sudo ldconfig
	@echo Library cache updated
endif

# Uninstall library from system
uninstall:
ifeq ($(DETECTED_OS),Windows)
	$(RM) $(INSTALL_DIR)$(PATH_SEP)$(LIB)
else
	sudo $(RM) $(INSTALL_DIR)/$(LIB)
	sudo ldconfig
endif
	@echo Library uninstalled

# Build with debug symbols
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

# Clean build artifacts
clean:
ifeq ($(DETECTED_OS),Windows)
	-@if exist $(OBJ_DIR) $(RMDIR) $(OBJ_DIR) 2>nul
	-@if exist $(LIB) $(RM) $(LIB) 2>nul
	-@if exist $(EXAMPLE) $(RM) $(EXAMPLE) 2>nul
else
	$(RMDIR) $(OBJ_DIR)
	$(RM) $(LIB) $(EXAMPLE)
endif
	@echo Clean complete

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Build library and example (default)"
	@echo "  install   - Install library to system"
	@echo "  uninstall - Remove library from system"
	@echo "  debug     - Build with debug symbols"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Detected OS: $(DETECTED_OS)"
	@echo "Library: $(LIB)"
	@echo "Install directory: $(INSTALL_DIR)"
