#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>

// ANSI Colors
#define RED "\e[0;31m"
#define GRN "\e[0;32m"

#define CRESET "\e[0m"

volatile void *__global_ptrauth_device_base;

uint64_t sign(uint64_t ptr, uint64_t tweak) {
    *(uint64_t*)(__global_ptrauth_device_base + 0x10) = ptr;
    *(uint64_t*)(__global_ptrauth_device_base + 0x18) = tweak;

    return  *(uint64_t*)(__global_ptrauth_device_base + 0x20);
}

uint64_t auth(uint64_t ptr, uint64_t tweak) {
    *(uint64_t*)(__global_ptrauth_device_base + 0x18) = tweak;
    *(uint64_t*)(__global_ptrauth_device_base + 0x20) = ptr;

    return  *(uint64_t*)(__global_ptrauth_device_base + 0x20);
}

static void signal_handler(int signo) {
    signal(SIGUSR1, &signal_handler);
    printf("[%d] Signal handler called! Signal: %s\n", getpid(), strsignal(signo));
}

void setup(void) {
    signal(SIGUSR1, &signal_handler);
    printf("Opening device\n");
    int fd = open("/dev/ptrauth", O_RDWR);

    printf("Memory Mapping\n");
    __global_ptrauth_device_base = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
}

void child(void) {
    printf("[%d] child process!\n", getpid());
    return;
}

int main(void) {
    setup();

    int pid = getpid();

    uint64_t ptr = 0x1234;
    uint64_t signed_ptr = sign(ptr, 0x10);
    printf("[%d] Signed pointer: %016llx\n", pid, signed_ptr);

    sleep(2);
    uint64_t auth_ptr = auth(signed_ptr, 0x10);


    if (auth_ptr != ptr) {
        printf(RED "[%d] Invalid auth pointer: %016llx\n" CRESET, pid, auth_ptr);
    } else {
        printf(GRN "[%d] Correct pointer!\n" CRESET, pid);
    }

    printf("\n[%d] Trying to authenticate invalid signal\n", pid);
    uint64_t auth_ptr_funny = auth(signed_ptr + 1, 0x10);
    printf("[%d] Authenticated ptr (should be all zeros): %016llx\n", pid, auth_ptr_funny);

}
