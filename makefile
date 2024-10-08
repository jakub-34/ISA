CC = g++
CFLAGS = -Wall

SRCS = p2nprobe.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = p2nprobe

LIBS = -lpcap

.PHONY: all clean

all: $(TARGET)

$(TARGET): 
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	$(RM) $(TARGET)