CC=g++
CPPFLAGS=-Wall -Wextra
LDFLAGS=
LDLIBS=

DEPS=transport.o io.o packet.o  # NOTE: Added packet.o to the dependencies

all: server client

server: server.o $(DEPS)
client: client.o $(DEPS)

clean:
	@rm -rf server client *.bin *.o
