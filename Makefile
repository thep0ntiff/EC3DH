CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinc -fPIC -g
LDFLAGS = -shared -lmodplus

SRC_DIR = src
OBJ_DIR = build
LIB = libec.so


SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

EXAMPLE := main
EXAMPLE_SRC := examples/main.c


all: $(LIB) $(EXAMPLE)

$(LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	sudo cp $(LIB) /lib

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(EXAMPLE): $(EXAMPLE_SRC)
	$(CC) -Wall -Wextra -Iinc -L. -o $@ $< -lec -g


$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(LIB) /lib/$(LIB) $(EXAMPLE)
