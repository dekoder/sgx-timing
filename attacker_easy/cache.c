#include "cache.h"
#include <stdio.h>
#include <string.h>
#include <cpuid.h>


static int alignment_dummy __attribute__ ((aligned(4096)));
static int alignment_dummy2 __attribute__ ((aligned(1024)));

static size_t round, table;
static size_t i, j;
static uint32_t t1, t2, mean;
static unsigned int local_hits_single, local_hits_sum;
static uint32_t pmccount;
static uint32_t pmc1, pmc2;	   //counter values before and after each test
static const int pmc_num = 0x00000001;	   //program monitor counter number for L1-Misses

/*
 * Force cpu to serialize instructions
 */
static inline void serialize () {
	__asm __volatile__ ("cpuid" : : "a"(0) : "ebx", "ecx", "edx" );  // serialize
}

/*
 * Read performance-counter instruction
 */
static inline uint64_t readpmc(int32_t n) {
	uint32_t lo, hi;
	__asm __volatile__ ("rdpmc" : "=a"(lo), "=d"(hi) : "c"(n) : );
	return lo | (uint64_t)hi << 32;
}



/*
 * Access a single cacheline in order to load it into the L1 cache.
 */
unsigned int prime_single(size_t entry, const uint8_t *table, size_t tablesize){
	__asm__ __volatile__(
					"cpuid				\n"
					/* Remove from every cache level */
					"movq (%%rsi), %%rbx\n"
					"cpuid				\n"
					: /* output operands */
					: /* input operands */
					"S" (table + CACHELINESIZE * entry)
					: /* clobber description */
					"ebx", "ecx", "edx", "cc"
		);
	return 0;
}

/*
 * Access single cachline and check PMC for L1-Cache miss.
 */
unsigned int measure_pmc(size_t entry, const uint8_t *table, size_t tablesize){
	local_hits_single = 0;

	serialize();					//prevent out-of-order execution
	pmc1 = (int)readpmc(pmc_num);	//read PMC

	__asm__ __volatile__(
			"movq (%%rsi), %%rbx\n"
			: /* output operands */
			: /* input operands */
			"S" (table + CACHELINESIZE * entry)
			: /* clobber description */
			"ebx", "ecx", "edx", "cc", "memory"
		);
	serialize();					// serialize again

	pmc2 = (int)readpmc(pmc_num);
	pmccount = pmc2-pmc1;

	return pmccount;
}

/*
 * Evict whole table from cache.
 */
unsigned int evict(const uint8_t *table, size_t tablesize, uint8_t *bitmap){
		for (i = 0; i < tablesize/CACHELINESIZE; i++) {
				__asm__ (
								"clflush (%%rsi)	 \n"
				: /* output operands */
				: /* input operands */
								"S" (table + CACHELINESIZE * i)
				: /* clobber description */
								"ebx", "ecx", "edx", "cc"
				);
	}
	return 0;
}

/*
 * Check for evicted cacheline in all cache-sets.
 */
unsigned int probe(size_t index) {
	int result = 0;
	for (table = 0; table < NUM_TABLES; table++) {
		result += measure_pmc(index, (const uint8_t *) tables[table], TABLESIZE) << ((NUM_TABLES - 1 - table) * 4);
	}
		
	return result;	
}

/*
 * Fill all cache-lines in every cache-set.
 */
void prime(void) {
	for (round = 0; round < 1; round++){
			for (table = 0; table < NUM_TABLES; table++) {
				for (i = 0; i < TABLESIZE/CACHELINESIZE; i++) {
					prime_single(i, (const uint8_t *) tables[table], TABLESIZE);
				}
			}
	}
}


uint32_t my_measure_pmc(uint8_t *table){
	local_hits_single = 0;

	serialize();					//prevent out-of-order execution
	pmc1 = (int)readpmc(pmc_num);	//read PMC

	__asm__ __volatile__(
			"movq (%%rsi), %%rbx\n"
			: /* output operands */
			: /* input operands */
			"S" (table)
			: /* clobber description */
			"ebx", "ecx", "edx", "cc", "memory"
		);
	serialize();					// serialize again

	pmc2 = (int)readpmc(pmc_num);
	pmccount = pmc2-pmc1;

	return pmccount;
}

/*
void my_prime_() {
	volatile register int table, i;
	for (table = 0; table < NUM_TABLES; table++) {
		for (i = 0; i < TABLESIZE/CACHELINESIZE; i++) {
			faddrs[table*4096+i*64];
		}
	}
}


uint32_t my_probe_(size_t index) {
	uint32_t result = 0;
	for (table = 0; table < NUM_TABLES; table++) {
		result += my_measure_pmc(faddrs+table*4096+i*64) << ((NUM_TABLES - 1 - table) * 4);
	}
		
	return result;	
}
*/

/*
 * Check for evicted cacheline in all cache-sets.
 */
unsigned int my_probe(size_t index) {
	int result = 0;
	for (table = 0; table < NUM_TABLES; table++) {
		result += my_measure_pmc(addr + (table << 12) + (index << 6)) << ((NUM_TABLES - 1 - table) * 4);
	}
		
	return result;	
}

unsigned int my_asm_probe(size_t index) {
	int result = 0;

				__asm__ __volatile__(
							"xor %%r8, %%r8\n" // i = 0
							"1:\n"
							"cmp $7, %%r8\n" // i <= 7
							"jg 4f\n"

							"movl %%r8d, %%esi\n"
							"movl %k2, %%edi\n"
							"shl $12, %%esi\n" 	// table * 4096
							"shl $6, %%edi\n" 	// index * 64
							"addl %%edi, %%esi\n"
							"leaq (%%rsi,%1,), %%rsi\n" // %rsi = faddrs + table * 4096 + index * 64

							"movl $1, %%ecx\n"
							"rdpmc\n"

							"movq (%%rsi), %%rsi\n" // rsi = addr_value

							"movl %%eax, %%esi\n"	// esi = pmc1

							"movl $1, %%ecx\n"
							"rdpmc\n"				// eax = pmc2

							"subl %%esi, %%eax\n"
							"addl %%eax, %k0\n"		// result += pmc2 - pmc1

							"inc %%r8\n"			// i++
							"jmp 1b\n"
							"4:\n"
							: // output operands
							"+r" (result)
							: // input operands 
							"r" (faddrs),
							"r" (index)
							: // clobber description
							"r8", "rax", "rcx", "rdx", "rsi", "rdi"
				);

	//printf("%x\n", result);

				/*
	for (table = 0; table < NUM_TABLES; table++) {
		result += my_measure_pmc(addr + (table << 12) + (index << 6)) << ((NUM_TABLES - 1 - table) * 4);
	}
	*/
		
	return result;
}

/*
 * Fill all cache-lines in every cache-set.
 */

void my_prime(void) {
			__asm__ __volatile__(
							"xor %%rax, %%rax\n"
							"1:\n"
							"cmp $7, %%rax\n"
							"jg 4f\n"
							"xor %%rbx, %%rbx\n"
							"2:\n"
							"cmp $16, %%rbx\n"
							"jg 3f\n"
							"movl %%eax, %%esi\n"
							"movl %%ebx, %%edi\n"
							"shl $12, %%esi\n"
							"shl $6, %%edi\n"
							"addl %%edi, %%esi\n"
							"leaq (%%rsi,%0,), %%rsi\n"
							"movq (%%rsi), %%rsi\n"
							"inc %%rbx\n"
							"jmp 2b\n"
							"3:\n"
							"inc %%rax\n"
							"jmp 1b\n"
							"4:\n"
							: // output operands
							: // input operands 
							"r" (faddrs)
							: // clobber description
							"rax", "rbx", "rsi", "rdi"
				);
}

void my_prime_i(size_t index) {
			__asm__ __volatile__(
							"xor %%rax, %%rax\n"	// i = 0
							"1:\n"

							"cmp $7, %%rax\n"		// i > 7
							"jg 2f\n"

							"movl %k1, %%edi\n"		// edi = index

							"movl %%eax, %%esi\n"	// esi = i
							"shl $12, %%esi\n"		// i = i*4096
							"shl $6, %%edi\n"		// index*64
							"addl %%edi, %%esi\n"	// = index*64+i*4096
							"leaq (%%rsi,%0,), %%rsi\n"
							"movq (%%rsi), %%rsi\n"	// visit faddrs+x

							"inc %%rax\n"			// i++
							"jmp 1b\n"
							"2:\n"

							: // output operands
							: // input operands 
							"r" (faddrs),
							"r" (index)
							: // clobber description
							"rax", "rsi", "rdi"
				);
}

void my_prime_four(size_t index) {
			__asm__ __volatile__(
							"xor %%rax, %%rax\n"	// i = 0
							"1:\n"

							"cmp $7, %%rax\n"		// i > 7
							"jg 2f\n"

							"movl %k1, %%edi\n"		// edi = index

							"movl %%eax, %%esi\n"	// esi = i
							"shl $12, %%esi\n"		// i = i*4096
							"shl $6, %%edi\n"		// index*64
							"addl %%edi, %%esi\n"	// = index*64+i*4096
							"leaq (%%rsi,%0,), %%rsi\n"
							"movq (%%rsi), %%rsi\n"	// visit faddrs+x

							"inc %%rax\n"			// i++
							"jmp 1b\n"
							"2:\n"

							: // output operands
							: // input operands 
							"r" (faddrs),
							"r" (index)
							: // clobber description
							"rax", "rbx", "rsi", "rdi"
				);
}

void my_prime_rt(void) {
			__asm__ __volatile__(
							"xor %%r8, %%r8\n"
							"1:\n"
							"cmp $7, %%r8\n"
							"jg 4f\n"
							"xor %%r9, %%r9\n"
							"2:\n"
							"cmp $16, %%r9\n"
							"jg 3f\n"
							"movl %%r8d, %%r10d\n"
							"movl %%r9d, %%r11d\n"
							"shl $12, %%r10d\n"
							"shl $6, %%r11d\n"
							"addl %%r11d, %%r10d\n"
							"leaq (%%r10,%0,), %%r10\n"
							"movq (%%r10), %%r10\n"
							"inc %%r9\n"
							"jmp 2b\n"
							"3:\n"
							"inc %%r8\n"
							"jmp 1b\n"
							"4:\n"
							: // output operands
							: // input operands 
							"r" (faddrs)
							: // clobber description
							"r8", "r9", "r10", "r11"
				);
}