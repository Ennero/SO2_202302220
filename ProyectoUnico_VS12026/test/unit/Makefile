CC = gcc
CFLAGS = -Wall -pthread
LDFLAGS = -ljansson

all: test_endpoints

test_endpoints: test_endpoints.c
	$(CC) $(CFLAGS) -o test_endpoints test_endpoints.c $(LDFLAGS)

clean:
	rm -f test_endpoints
