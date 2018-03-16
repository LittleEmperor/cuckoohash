/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RTE_CUCKOO_HASH_H_
#define _RTE_CUCKOO_HASH_H_

#include <emmintrin.h>
#include "libringbuf.h"
#include "libcuckoohash.h"

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to algin
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t
_align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

/**
 * Returns true if n is a power of 2
 * @param n
 *     Number to check
 * @return 1 if true, 0 otherwise
 */
static inline int
_is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

#define RTE_PTR_ADD(ptr, x) ((void*)((uintptr_t)(ptr) + (x)))
#define RTE_ARCH_X86

/* Macro to enable/disable run-time checking of function parameters */
#if defined(RTE_LIBRTE_HASH_DEBUG)
#define RETURN_IF_TRUE(cond, retval) do { \
	if (cond) \
		return retval; \
} while (0)
#else
#define RETURN_IF_TRUE(cond, retval)
#endif

/* Hash function used if none is specified */
#include "jhash.h"
#define DEFAULT_HASH_FUNC       rte_jhash

#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM64)
/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
enum cmp_jump_table_case {
	KEY_CUSTOM = 0,
	KEY_16_BYTES,
	KEY_32_BYTES,
	KEY_48_BYTES,
	KEY_64_BYTES,
	KEY_80_BYTES,
	KEY_96_BYTES,
	KEY_112_BYTES,
	KEY_128_BYTES,
	KEY_OTHER_BYTES,
	NUM_KEY_CMP_CASES,
};

/*
 * Table storing all different key compare functions
 * (multi-process supported)
 */
/* const libcuckoohash_cmp_eq_t cmp_jump_table[NUM_KEY_CMP_CASES] = { */
/* 	NULL, */
/* 	libcuckoohash_k16_cmp_eq, */
/* 	libcuckoohash_k32_cmp_eq, */
/* 	libcuckoohash_k48_cmp_eq, */
/* 	libcuckoohash_k64_cmp_eq, */
/* 	libcuckoohash_k80_cmp_eq, */
/* 	libcuckoohash_k96_cmp_eq, */
/* 	libcuckoohash_k112_cmp_eq, */
/* 	libcuckoohash_k128_cmp_eq, */
/* 	memcmp */
/* }; */
#else
/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
enum cmp_jump_table_case {
	KEY_CUSTOM = 0,
	KEY_OTHER_BYTES,
	NUM_KEY_CMP_CASES,
};

/*
 * Table storing all different key compare functions
 * (multi-process supported)
 */
const libcuckoohash_cmp_eq_t cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL,
	memcmp
};

#endif

enum add_key_case {
	ADD_KEY_SINGLEWRITER = 0,
	ADD_KEY_MULTIWRITER,
	ADD_KEY_MULTIWRITER_TM,
};

/** Number of items per bucket. */
#define RTE_HASH_BUCKET_ENTRIES		8

#define NULL_SIGNATURE			0

#define EMPTY_SLOT			0

#define KEY_ALIGNMENT			16

#define LCORE_CACHE_SIZE		64

#define RTE_HASH_MAX_PUSHES             100

#define RTE_HASH_BFS_QUEUE_MAX_LEN       1000

#define RTE_XABORT_CUCKOO_PATH_INVALIDED 0x4

#define RTE_HASH_TSX_MAX_RETRY  10

/* Structure that stores key-value pair */
struct libcuckoohash_key {
	union {
		uintptr_t idata;
		void *pdata;
	};
	/* Variable key size */
	char key[0];
} __attribute__((aligned(KEY_ALIGNMENT)));

/* All different signature compare functions */
enum libcuckoohash_sig_compare_function {
	RTE_HASH_COMPARE_SCALAR = 0,
	RTE_HASH_COMPARE_SSE,
	RTE_HASH_COMPARE_AVX2,
	RTE_HASH_COMPARE_NUM
};

/** Bucket structure */
struct libcuckoohash_bucket {
	hash_sig_t sig_current[RTE_HASH_BUCKET_ENTRIES];

	uint32_t key_idx[RTE_HASH_BUCKET_ENTRIES];

	hash_sig_t sig_alt[RTE_HASH_BUCKET_ENTRIES];

	uint8_t flag[RTE_HASH_BUCKET_ENTRIES];
};

/** A hash table structure. */
struct cuckoo_hash{
	uint32_t entries;               /**< Total table entries. */
	uint32_t num_buckets;           /**< Number of buckets in table. */

	struct ringbuf *free_slots;
	/**< Ring that stores all indexes of the free slots in the key table */

	/* Fields used in lookup */
	uint32_t key_len;
	/**< Length of hash key. */
	libcuckoohash_function hash_func;    /**< Function used to calculate hash. */
	uint32_t hash_func_init_val;    /**< Init value used by hash_func. */
	libcuckoohash_cmp_eq_t libcuckoohash_custom_cmp_eq;
	/**< Custom function used to compare keys. */
	enum cmp_jump_table_case cmp_jump_table_idx;
	/**< Indicates which compare function to use. */
	enum libcuckoohash_sig_compare_function sig_cmp_fn;
	/**< Indicates which signature compare function to use. */
	uint32_t bucket_bitmask;
	/**< Bitmask for getting bucket index from hash signature. */
	uint32_t key_entry_size;         /**< Size of each key entry. */

	void *key_store;                /**< Table storing all keys and data */
	struct libcuckoohash_bucket *buckets;
	/**< Table with buckets storing all the	hash values and key indexes
	 * to the key table.
	 */
};

struct queue_node {
	struct libcuckoohash_bucket *bkt; /* Current bucket on the bfs search */

	struct queue_node *prev;     /* Parent(bucket) in search path */
	int prev_slot;               /* Parent(slot) in search path */
};

#endif
