#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

int main(void) {
    printf("Opening device\n");
    int fd = open("/dev/ptrauth", O_RDWR);

    printf("Memory Mapping\n");
    volatile uint64_t *registers = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    volatile uint64_t *plaintext  = registers + 0x10 / sizeof(uint64_t);
    volatile uint64_t *tweak      = registers + 0x18 / sizeof(uint64_t);
    volatile uint64_t *ciphertext = registers + 0x20 / sizeof(uint64_t);

    uint64_t encrypted_pointer;
    uint64_t decrypted_pointer;
    uint64_t tmp;
    int pid = getpid();

    uint64_t original_pointer = 0xABAB;

    // Tweak
    *tweak = 0x10;

    // ptr
    *plaintext = original_pointer;

    encrypted_pointer = *ciphertext;
    tmp = *ciphertext;

    printf("[%d] Original  pointer: %016llx\n", pid, original_pointer);
    printf("[%d] Encrypted pointer: %016llx (second read: %016llx)\n", pid, encrypted_pointer, tmp);
    sleep(2);

    *tweak = 0x10;
    *ciphertext = encrypted_pointer;
    decrypted_pointer = *ciphertext;
    tmp = *ciphertext;

    printf("[%d] Decrypted pointer: %016llx (second read: %016llx)\n", pid, decrypted_pointer, tmp);

    encrypted_pointer += 0x10;
    *tweak = 0x10;
    *ciphertext = encrypted_pointer;
    decrypted_pointer = *ciphertext;

    printf("[%d] Modified encrypter pointer: %016llx\n", pid, encrypted_pointer);
    printf("[%d] Decrypted modified encrypter pointer: %016llx\n", pid,  decrypted_pointer);

    printf("Closing Device\n");
    close(fd);
}
