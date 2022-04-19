.PHONY: all build test clean

CC = g++
BUILD_FLAGS = \
	-std=gnu++2a -pedantic -Wall \
	-Wno-missing-braces -Wextra -Wno-missing-field-initializers -Wformat=2 \
	-Wswitch-default -Wswitch-enum -Wcast-align -Wpointer-arith \
	-Wstrict-overflow=5 -Winline \
	-Wundef -Wcast-qual -Wshadow -Wunreachable-code \
	-Wlogical-op -Wfloat-equal -Wstrict-aliasing=2 -Wredundant-decls \
	-Wno-pedantic-ms-format -Werror \
	-g -O0 \
	-fno-omit-frame-pointer -ffloat-store -fno-common

ifeq ($(OS),Windows_NT)
	LINK_FLAGS = -lWs2_32
	COPY_HEADERS = xcopy /s /y src\*.hpp bin\include >NUL
	TEST_BINARY = bin\test
	POST_BUILD_CMD = cd.
	CLEAN_CMD = del bin\cppdtp bin\cppdtp.exe bin\test bin\test.exe bin\include\*.hpp
else
	LINK_FLAGS = -lpthread -lm
	COPY_HEADERS = cp src/*.hpp bin/include/
	TEST_BINARY = ./bin/test
	POST_BUILD_CMD = chmod +x ./bin/test
	CLEAN_CMD = rm -f bin/cppdtp bin/cppdtp.exe bin/test bin/test.exe bin/include/*.hpp
endif

all: build

build:
	$(COPY_HEADERS) && \
	$(CC) -o bin/test \
		$(BUILD_FLAGS) \
		test/*.cpp \
		$(LINK_FLAGS) && \
	$(POST_BUILD_CMD)

test:
	$(TEST_BINARY)

clean:
	$(CLEAN_CMD)
