# Compiler
CC := gcc

# Compiler flags
CFLAGS := -Wall -Wextra -I./headers

# Source files
SRCS := $(wildcard ./source/*.c)

# Object files
OBJS := $(SRCS:.c=.o)

# Target executable
TARGET := ./bin/test

# Default target
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# Rule to build object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(TARGET)