CC = gcc
CFLAGS = -Wall -Wextra -pthread -g
TARGET = mutex_test
SOURCE = mutex_test.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

.PHONY: all clean