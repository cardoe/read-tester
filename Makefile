.PHONY: all
all: reader

reader_LDFLAGS=$(LDFLAGS)
reader_CFLAGS=-std=gnu99 -Wall -Wextra -Og -g $(CFLAGS)
reader_LIBS=-lcrypto

%: %.c
	$(CC) $(reader_LDFLAGS) $(reader_CFLAGS) -o $@ $< $(reader_LIBS)
