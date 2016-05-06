#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/md5.h>

struct common_state {
    int fd;
    size_t block_size;
    ssize_t file_len;
    size_t md_len;
    uint8_t *buf;
    size_t pos;
    MD5_CTX ctx;
};

void common_start(struct common_state *state, int fd, size_t block_size,
        size_t seek_offset, size_t md_len);
void common_finish(struct common_state *state);

void die(int errnum, const char *fmt, ...)
    __attribute__ ((noreturn));

int do_normal_read(struct common_state *state);
int do_iovec_read(struct common_state *state);
int do_mmap_read(struct common_state *state);

void
usage(void) {
    printf(
"usage: reader [-n | -v | -d | -m] [-b SIZE] [-s SIZE] FILENAME\n"
"\n"
"\t-n\t\tuse read() calls\n"
"\t-v\t\tuse readv() calls\n"
"\t-d\t\tuse read() calls but open the file with O_DIRECT\n"
"\t-m\t\tuse mmap() and read chunks from the mapped region\n"
"\t-b SIZE\tread in SIZE chunks\n"
"\t-s SIZE\tseek SIZE into the file before reading\n"
);
    exit(EXIT_FAILURE);
}

void
print_hash(uint8_t *buf, size_t len)
{
    for (size_t x = 0; x < len; x++) {
        printf("%02x", buf[x]);
    }
}

void
die(int errnum, const char *fmt, ...)
{
    va_list ap;
    char *real_fmt = NULL;

    if (errnum != -1) {
        if (asprintf(&real_fmt, "%%s: %s\n", strerror(errnum)) == -1)
            exit(EXIT_FAILURE);
    } else {
        if (asprintf(&real_fmt, "%%s\n") == -1)
            exit(EXIT_FAILURE);
    }

    va_start(ap, fmt);
    vfprintf(stderr, real_fmt, ap);
    va_end(ap);

    free(real_fmt);
    exit(EXIT_FAILURE);
}

void
common_start(struct common_state *state, int fd, size_t block_size,
        size_t seek_offset, size_t md_len)
{
    state->fd = fd;
    state->block_size = block_size;
    state->pos = 0;
    state->md_len = md_len;

    state->file_len = lseek(state->fd, 0, SEEK_END);
    if (state->file_len == -1) {
        die(errno, "Failed to seek to end of the file.");
    }

    if (lseek(fd, seek_offset, SEEK_SET) == -1) {
        die(errno, "Failed to seek %zd byte(s) into the file.", seek_offset);
    }


    if (MD5_Init(&state->ctx) == 0) {
        die(-1, "Unable to initialize MD5 context");
    }

    state->buf = malloc(state->block_size);
    if (state->buf == NULL) {
        die(errno, "Unable to allocate %zu byte(s).", state->block_size);
    }

}

void
common_finish(struct common_state *state)
{
    uint8_t hash[EVP_MAX_MD_SIZE];

    close(state->fd);
    free(state->buf);

    MD5_Final(hash, &state->ctx);

    printf("%8s:%08zu:", "final", state->pos);
    print_hash(hash, state->md_len);
    printf("\n");
}

int
do_normal_read(struct common_state *state)
{
    ssize_t count;
    uint8_t hash[EVP_MAX_MD_SIZE];

    // read to the end
    do {
        // perform the actual read
        count = read(state->fd, state->buf, state->block_size);
        if (count == -1) {
            die(errno, "Unable to read from file");
        }

        MD5(state->buf, count, hash);
        MD5_Update(&state->ctx, state->buf, count);
        printf("%08zu:%08zu:", state->pos, count);
        print_hash(hash, state->md_len);
        printf("\n");

        state->pos += count;
    } while (count != 0);

    return 0;
}

int
do_mmap_read(struct common_state *state)
{
    void *buf;
    size_t left;
    size_t count = state->block_size;
    uint8_t hash[EVP_MAX_MD_SIZE];

    left = state->file_len;

    buf = mmap(NULL, state->file_len, PROT_READ, MAP_PRIVATE, state->fd, 0);
    if (buf == MAP_FAILED) {
        die(errno, "Unable to mmap() file");
    }

    // read through all the data in block size chunks
    while (left > 0) {
        MD5(buf + state->pos, count, hash);
        MD5_Update(&state->ctx, buf + state->pos, count);
        printf("%08zu:%08zu:", state->pos, count);
        print_hash(hash, state->md_len);
        printf("\n");

        state->pos += count;
        left -= count;
        if (left < count)
            count = left;
    }

    munmap(buf, state->file_len);
    return 0;
}

int
do_iovec_read(struct common_state *state)
{
    return -1;
}

enum read_mode {
    NORMAL_READ,
    IOVEC_READ,
    MMAP_READ,
};

int
main(int argc, char * const argv[])
{
    int fd;
    int open_flags = O_RDONLY;
    int opt;
    enum read_mode mode = NORMAL_READ;
    size_t block_size = 4096;
    ssize_t seek_offset = 0;
    const char *filename = NULL;
    struct common_state state;

    while ((opt = getopt(argc, argv, "nvdmb:s:")) != -1) {
        switch (opt) {
            case 'n':  // read()
                mode = NORMAL_READ;
                break;
            case 'v': // readv()
                mode = IOVEC_READ;
                break;
            case 'd': // read()
                mode = NORMAL_READ;
                open_flags |= O_DIRECT;
                break;
            case 'm': // mmap()
                mode = MMAP_READ;
                break;
            case 'b':
                block_size = atoi(optarg);
                break;
            case 's':
                seek_offset = atoi(optarg);
                break;
            default: // '?'
                usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected filename after options\n\n");
        usage();
        exit(EXIT_FAILURE);
    }

    // the file we'll be working with
    filename = argv[optind];

    printf("File: %s\n", filename);
    switch (mode) {
        case NORMAL_READ:
            printf("Using read()\n");
            break;
        case IOVEC_READ:
            printf("Using readv()\n");
            break;
        case MMAP_READ:
            printf("Using mmap() and reading from mapped region\n");
            break;
    }

    printf("Open Flags: ");
    if (open_flags & O_DIRECT)
        printf("O_DIRECT ");
    printf("\n");

    printf("Seek offset into file %zd byte(s).\n", seek_offset);

    printf("Reads will happen in a block size of %zu byte(s).\n", block_size);

    fd = open(filename, open_flags);
    if (fd == -1) {
        die(errno, "Unable to open '%s'", argv[1]);
    }

    common_start(&state, fd, block_size, seek_offset, MD5_DIGEST_LENGTH);

    switch (mode) {
        case NORMAL_READ:
            do_normal_read(&state);
            break;
        case IOVEC_READ:
            do_iovec_read(&state);
            break;
        case MMAP_READ:
            do_mmap_read(&state);
            break;
    }

    common_finish(&state);

    return EXIT_SUCCESS;
}
