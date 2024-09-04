#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

int main(void) {
    printf("Opening device\n");
    int fd = open("/dev/ptrauth", O_RDWR);

    printf("Memory Mapping\n");
    uint64_t *key = mmap(NULL, 16, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    printf("key low: %llx\nkey high: %llx\n", key[0], key[1]);


    printf("Closing Device\n");
    close(fd);
}
