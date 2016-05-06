.PHONY: all
all: reader

%: %.c
	$(CC) -std=gnu99 -Wall -Wextra -Og -g -o $@ $< -lcrypto
