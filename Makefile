.PHONY: all build test clean

CC = g++
BUILD_FLAGS = \
	-std=gnu++2a -pedantic -Wall \
	-Wno-missing-braces -Wextra -Wno-missing-field-initializers -Wformat=2 \
	-Wswitch-default -Wswitch-enum -Wcast-align -Wpointer-arith \
	-Wstrict-overflow=5 -Winline \
	-Wundef -Wcast-qual -Wshadow -Wunreachable-code \
	-Wlogical-op -Wfloat-equal -Wstrict-aliasing=2 -Wredundant-decls \
	-Werror \
	-g -O0 \
	-fno-omit-frame-pointer -ffloat-store -fno-common

ifeq ($(OS),Windows_NT)
	LINK_FLAGS = -lWs2_32
	TEST_BINARY = bin\test
	POST_BUILD_CMD = cd.
	CLEAN_CMD = del bin\cppdtp bin\cppdtp.exe bin\test bin\test.exe
else
	LINK_FLAGS = -lpthread -lm
	TEST_BINARY = ./bin/test
	POST_BUILD_CMD = chmod +x ./bin/test
	CLEAN_CMD = rm -f bin/cppdtp bin/cppdtp.exe bin/test bin/test.exe
endif

all: build

build:
	$(CC) -o bin/test \
		$(BUILD_FLAGS) \
		test/*.cpp \
		$(LINK_FLAGS) && \
	$(POST_BUILD_CMD)

test:
	$(TEST_BINARY)

clean:
	$(CLEAN_CMD)
