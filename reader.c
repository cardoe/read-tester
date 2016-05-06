#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>

void die(int errnum, const char *fmt, ...)
    __attribute__ ((noreturn));

int do_normal_read(int fd, size_t block_size);
int do_iovec_read(int fd, size_t block_size);
int do_mmap_read(int fd, size_t block_size);

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

int
do_normal_read(int fd, size_t block_size)
{
    uint8_t *buf = NULL;
    size_t pos = 0;
    MD5_CTX ctx;
    uint8_t hash[MD5_DIGEST_LENGTH];
    ssize_t count;

    if (MD5_Init(&ctx) == 0) {
        die(-1, "Unable to initialize MD5 context");
    }

    buf = malloc(block_size);
    if (buf == NULL) {
        die(errno, "Unable to allocate %zu byte(s).", block_size);
    }

    // read to the end
    do {
        // perform the actual read
        count = read(fd, buf, block_size);
        if (count == -1) {
            die(errno, "Unable to read from file");
        }

        MD5(buf, count, hash);
        MD5_Update(&ctx, buf, count);
        printf("%08zu:%08zu:", pos, count);
        print_hash(hash, MD5_DIGEST_LENGTH);
        printf("\n");

        pos += count;
    } while (count != 0);

    MD5_Final(hash, &ctx);

    printf("%8s:%08zu:", "final", pos);
    print_hash(hash, MD5_DIGEST_LENGTH);
    printf("\n");

    return 0;
}

int
do_iovec_read(int fd, size_t block_size)
{
    return -1;
}

int
do_mmap_read(int fd, size_t block_size)
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
    ssize_t seek_offset = -1;
    const char *filename = NULL;

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
                printf("usage here");
                //usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        die(-1, "Expected filename after options");
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

    if (seek_offset != -1) {
        printf("Seek offset into file %zd byte(s).\n", seek_offset);
    }

    printf("Reads will happen in a block size of %zu byte(s).\n", block_size);

    fd = open(filename, open_flags);
    if (fd == -1) {
        die(errno, "Unable to open '%s'", argv[1]);
    }

    if (seek_offset != -1 && lseek(fd, seek_offset, SEEK_CUR) == -1) {
        die(errno, "Failed to seek %zd byte(s) into the file.", seek_offset);
    }

    switch (mode) {
        case NORMAL_READ:
            do_normal_read(fd, block_size);
            break;
        case IOVEC_READ:
            do_iovec_read(fd, block_size);
            break;
        case MMAP_READ:
            do_mmap_read(fd, block_size);
            break;
    }

    close(fd);

    return EXIT_SUCCESS;
}
