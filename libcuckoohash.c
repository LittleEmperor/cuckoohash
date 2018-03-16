/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/queue.h>

#include "cuckoohash_struct.h"
#include "lib/libcuckoohash.h"

#if defined(RTE_ARCH_X86)
#include "cuckoohash_x86.h"
#endif

#define CUCKOO_MAKE_ROOM_DEPTH 8

const libcuckoohash_cmp_eq_t cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL,
	libcuckoohash_k16_cmp_eq,
	libcuckoohash_k32_cmp_eq,
	libcuckoohash_k48_cmp_eq,
	libcuckoohash_k64_cmp_eq,
	libcuckoohash_k80_cmp_eq,
	libcuckoohash_k96_cmp_eq,
	libcuckoohash_k112_cmp_eq,
	libcuckoohash_k128_cmp_eq,
	memcmp
};

void libcuckoohash_set_cmp_func(struct cuckoo_hash *h, libcuckoohash_cmp_eq_t func)
{
	h->cmp_jump_table_idx = KEY_CUSTOM;
	h->libcuckoohash_custom_cmp_eq = func;
}

static inline int
libcuckoohash_cmp_eq(const void *key1, const void *key2, const struct cuckoo_hash *h)
{
	if (h->cmp_jump_table_idx == KEY_CUSTOM)
		return h->libcuckoohash_custom_cmp_eq(key1, key2, h->key_len);
	else
		return cmp_jump_table[h->cmp_jump_table_idx](key1, key2, h->key_len);
}

struct cuckoo_hash *
libcuckoohash_create(const struct libcuckoohash_parameters *params)
{
	struct cuckoo_hash *h = NULL;
	struct ringbuf *r = NULL;
	void *k = NULL;
	void *buckets = NULL;
	unsigned num_key_slots;
	unsigned i;

	/* Check for valid parameters */
	if ((params->entries > RTE_HASH_ENTRIES_MAX) ||
			(params->entries < RTE_HASH_BUCKET_ENTRIES) ||
			!_is_power_of_2(RTE_HASH_BUCKET_ENTRIES) ||
			(params->key_len == 0)) {
		printf("libcuckoohash_create has invalid parameters\n");
		return NULL;
	}


	num_key_slots = params->entries + 1;

	r = libringbuf_create(_align32pow2(num_key_slots - 1), 0);
	if (r == NULL) {
		printf("memory allocation failed\n");
		goto err;
	}

	h = (struct cuckoo_hash *)malloc(sizeof(struct cuckoo_hash));
	if (h == NULL) {
		printf("memory allocation failed\n");
		goto err;
	}

	const uint32_t num_buckets = _align32pow2(params->entries)
					/ RTE_HASH_BUCKET_ENTRIES;

	buckets = malloc(num_buckets * sizeof(struct libcuckoohash_bucket));
	if (buckets == NULL) {
		printf("memory allocation failed\n");
		goto err;
	}

	const uint32_t key_entry_size = sizeof(struct libcuckoohash_key) + params->key_len;
	const uint64_t key_tbl_size = (uint64_t) key_entry_size * num_key_slots;

	k = malloc(key_tbl_size);

	if (k == NULL) {
		printf("memory allocation failed\n");
		goto err;
	}

/*
 * If x86 architecture is used, select appropriate compare function,
 * which may use x86 intrinsics, otherwise use memcmp
 */
	/* Select function to compare keys */
	switch (params->key_len) {
	case 16:
		h->cmp_jump_table_idx = KEY_16_BYTES;
		break;
	case 32:
		h->cmp_jump_table_idx = KEY_32_BYTES;
		break;
	case 48:
		h->cmp_jump_table_idx = KEY_48_BYTES;
		break;
	case 64:
		h->cmp_jump_table_idx = KEY_64_BYTES;
		break;
	case 80:
		h->cmp_jump_table_idx = KEY_80_BYTES;
		break;
	case 96:
		h->cmp_jump_table_idx = KEY_96_BYTES;
		break;
	case 112:
		h->cmp_jump_table_idx = KEY_112_BYTES;
		break;
	case 128:
		h->cmp_jump_table_idx = KEY_128_BYTES;
		break;
	default:
		/* If key is not multiple of 16, use generic memcmp */
		h->cmp_jump_table_idx = KEY_OTHER_BYTES;
	}

	/* Setup hash context */
	h->entries = params->entries;
	h->key_len = params->key_len;
	h->key_entry_size = key_entry_size;
	h->hash_func_init_val = params->hash_func_init_val;

	h->num_buckets = num_buckets;
	h->bucket_bitmask = h->num_buckets - 1;
	h->buckets = buckets;
	h->hash_func = (params->hash_func == NULL) ?
		DEFAULT_HASH_FUNC : params->hash_func;
	h->key_store = k;
	h->free_slots = r;

	h->sig_cmp_fn = RTE_HASH_COMPARE_SCALAR;

		//h->add_key = ADD_KEY_SINGLEWRITER;

	/* Populate free slots ring. Entry zero is reserved for key misses. */
	for (i = 1; i < params->entries + 1; i++)
		libringbuf_sp_enqueue(r, (void *)((uintptr_t) i));

	return h;
err:
	libringbuf_free(r);
	free(h);
	free(buckets);
	free(k);
	return NULL;
}

void
libcuckoohash_free(struct cuckoo_hash *h)
{
	if (h == NULL)
		return;

	libringbuf_free(h->free_slots);
	free(h->key_store);
	free(h->buckets);
	free(h);
}

hash_sig_t
libcuckoohash_hash(const struct cuckoo_hash *h, const void *key)
{
	/* calc hash result by key */
	return h->hash_func(key, h->key_len, h->hash_func_init_val);
}

/* Calc the secondary hash value from the primary hash value of a given key */
static inline hash_sig_t
libcuckoohash_secondary_hash(const hash_sig_t primary_hash)
{
	static const unsigned all_bits_shift = 12;
	static const unsigned alt_bits_xor = 0x5bd1e995;

	uint32_t tag = primary_hash >> all_bits_shift;

	return primary_hash ^ ((tag + 1) * alt_bits_xor);
}

void
libcuckoohash_reset(struct cuckoo_hash *h)
{
	void *ptr;
	unsigned i;

	if (h == NULL)
		return;

	memset(h->buckets, 0, h->num_buckets * sizeof(struct libcuckoohash_bucket));
	memset(h->key_store, 0, h->key_entry_size * (h->entries + 1));

	/* clear the free ring */
	while (libringbuf_dequeue(h->free_slots, &ptr) == 0)
		;

	/* Repopulate the free slots ring. Entry zero is reserved for key misses */
	for (i = 1; i < h->entries + 1; i++)
		libringbuf_sp_enqueue(h->free_slots, (void *)((uintptr_t) i));
}

/* Search for an entry that can be pushed to its alternative location */
static inline int
make_space_bucket(const struct cuckoo_hash *h, struct libcuckoohash_bucket *bkt, const int depth)
{
	static unsigned int nr_pushes;
	unsigned i, j;
	int ret;
	uint32_t next_bucket_idx;
	struct libcuckoohash_bucket *next_bkt[RTE_HASH_BUCKET_ENTRIES];

	if (depth == 0) {
		return -ENOSPC;
	}

	/*
	 * Push existing item (search for bucket with space in
	 * alternative locations) to its alternative location
	 */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		/* Search for space in alternative locations */
		next_bucket_idx = bkt->sig_alt[i] & h->bucket_bitmask;
		next_bkt[i] = &h->buckets[next_bucket_idx];
		for (j = 0; j < RTE_HASH_BUCKET_ENTRIES; j++) {
			if (next_bkt[i]->key_idx[j] == EMPTY_SLOT)
				break;
		}

		if (j != RTE_HASH_BUCKET_ENTRIES)
			break;
	}

	/* Alternative location has spare room (end of recursive function) */
	if (i != RTE_HASH_BUCKET_ENTRIES) {
		next_bkt[i]->sig_alt[j] = bkt->sig_current[i];
		next_bkt[i]->sig_current[j] = bkt->sig_alt[i];
		next_bkt[i]->key_idx[j] = bkt->key_idx[i];
		return i;
	}

	/* Pick entry that has not been pushed yet */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++)
		if (bkt->flag[i] == 0)
			break;

	/* All entries have been pushed, so entry cannot be added */
	if (i == RTE_HASH_BUCKET_ENTRIES || nr_pushes > RTE_HASH_MAX_PUSHES)
		return -ENOSPC;

	/* Set flag to indicate that this entry is going to be pushed */
	bkt->flag[i] = 1;

	nr_pushes++;
	/* Need room in alternative bucket to insert the pushed entry */
	ret = make_space_bucket(h, next_bkt[i], depth - 1);
	/*
	 * After recursive function.
	 * Clear flags and insert the pushed entry
	 * in its alternative location if successful,
	 * or return error
	 */
	bkt->flag[i] = 0;
	nr_pushes = 0;
	if (ret >= 0) {
		next_bkt[i]->sig_alt[ret] = bkt->sig_current[i];
		next_bkt[i]->sig_current[ret] = bkt->sig_alt[i];
		next_bkt[i]->key_idx[ret] = bkt->key_idx[i];
		return i;
	} else
		return ret;

}

/*
 * Function called to enqueue back an index in the cache/ring,
 * as slot has not being used and it can be used in the
 * next addition attempt.
 */
static inline void
enqueue_slot_back(const struct cuckoo_hash *h,
		void *slot_id)
{
		libringbuf_sp_enqueue(h->free_slots, slot_id);
}

static inline int32_t
__libcuckoohash_add_key_with_hash(const struct cuckoo_hash *h, const void *key,
						hash_sig_t sig, void *data)
{
	hash_sig_t alt_hash;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	unsigned i;
	struct libcuckoohash_bucket *prim_bkt, *sec_bkt;
	struct libcuckoohash_key *new_k, *k, *keys = h->key_store;
	void *slot_id = NULL;
	uint32_t new_idx;
	int ret;
	unsigned n_slots;
	unsigned lcore_id;

	prim_bucket_idx = sig & h->bucket_bitmask;
	prim_bkt = &h->buckets[prim_bucket_idx];
//	rte_prefetch0(prim_bkt);

	alt_hash = libcuckoohash_secondary_hash(sig);
	sec_bucket_idx = alt_hash & h->bucket_bitmask;
	sec_bkt = &h->buckets[sec_bucket_idx];
//	rte_prefetch0(sec_bkt);
		if (libringbuf_sc_dequeue(h->free_slots, &slot_id) != 0)
			return -ENOSPC;

	new_k = RTE_PTR_ADD(keys, (uintptr_t)slot_id * h->key_entry_size);
//	rte_prefetch0(new_k);
	new_idx = (uint32_t)((uintptr_t) slot_id);

	/* Check if key is already inserted in primary location */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (prim_bkt->sig_current[i] == sig &&
				prim_bkt->sig_alt[i] == alt_hash) {
			k = (struct libcuckoohash_key *) ((char *)keys +
					prim_bkt->key_idx[i] * h->key_entry_size);
			if (libcuckoohash_cmp_eq(key, k->key, h) == 0) {
				/* Enqueue index of free slot back in the ring. */
				enqueue_slot_back(h,slot_id);
				/* Update data */
				k->pdata = data;
				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				return prim_bkt->key_idx[i] - 1;
			}
		}
	}

	/* Check if key is already inserted in secondary location */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (sec_bkt->sig_alt[i] == sig &&
				sec_bkt->sig_current[i] == alt_hash) {
			k = (struct libcuckoohash_key *) ((char *)keys +
					sec_bkt->key_idx[i] * h->key_entry_size);
			if (libcuckoohash_cmp_eq(key, k->key, h) == 0) {
				/* Enqueue index of free slot back in the ring. */
				enqueue_slot_back(h, slot_id);
				/* Update data */
				k->pdata = data;
				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				return sec_bkt->key_idx[i] - 1;
			}
		}
	}

	/* Copy key */
	memcpy(new_k->key, key, h->key_len);
	new_k->pdata = data;

		for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
			/* Check if slot is available */
			if (prim_bkt->key_idx[i] == EMPTY_SLOT) {
				prim_bkt->sig_current[i] = sig;
				prim_bkt->sig_alt[i] = alt_hash;
				prim_bkt->key_idx[i] = new_idx;
				break;
			}
		}

		if (i != RTE_HASH_BUCKET_ENTRIES) {
			return new_idx - 1;
		}

		/* Primary bucket full, need to make space for new entry
		 * After recursive function.
		 * Insert the new entry in the position of the pushed entry
		 * if successful or return error and
		 * store the new slot back in the ring
		 */
		ret = make_space_bucket(h, prim_bkt, CUCKOO_MAKE_ROOM_DEPTH);
		if (ret >= 0) {
			prim_bkt->sig_current[ret] = sig;
			prim_bkt->sig_alt[ret] = alt_hash;
			prim_bkt->key_idx[ret] = new_idx;
			return new_idx - 1;
		}
	/* Error in addition, store new slot back in the ring and return error */
	enqueue_slot_back(h, (void *)((uintptr_t) new_idx));

	return ret;
}

int32_t
libcuckoohash_add_key_with_hash(const struct cuckoo_hash *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_add_key_with_hash(h, key, sig, 0);
}

int32_t
libcuckoohash_add_key(const struct cuckoo_hash *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_add_key_with_hash(h, key, libcuckoohash_hash(h, key), 0);
}

int
libcuckoohash_add_key_with_hash_data(const struct cuckoo_hash *h,
			const void *key, hash_sig_t sig, void *data)
{
	int ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	ret = __libcuckoohash_add_key_with_hash(h, key, sig, data);
	if (ret >= 0)
		return 0;
	else
		return ret;
}

int
libcuckoohash_add_key_data(const struct cuckoo_hash *h, const void *key, void *data)
{
	int ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	ret = __libcuckoohash_add_key_with_hash(h, key, libcuckoohash_hash(h, key), data);
	if (ret >= 0)
		return 0;
	else
		return ret;
}

int
libcuckoohash_get_bucket_pos(const struct cuckoo_hash *h, hash_sig_t sig)
{

        RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
            return RTE_HASH_BUCKET_ENTRIES*(sig & h->bucket_bitmask);
}

static inline int32_t
__libcuckoohash_lookup_with_hash(const struct cuckoo_hash *h, const void *key,
					hash_sig_t sig, void **data)
{
	uint32_t bucket_idx;
	hash_sig_t alt_hash;
	unsigned i;
	struct libcuckoohash_bucket *bkt;
	struct libcuckoohash_key *k, *keys = h->key_store;

	bucket_idx = sig & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in primary location */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig &&
				bkt->key_idx[i] != EMPTY_SLOT) {
			k = (struct libcuckoohash_key *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (libcuckoohash_cmp_eq(key, k->key, h) == 0) {
				if (data != NULL)
					*data = k->pdata;
				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}

	/* Calculate secondary hash */
	alt_hash = libcuckoohash_secondary_hash(sig);
	bucket_idx = alt_hash & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in secondary location */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == alt_hash &&
				bkt->sig_alt[i] == sig) {
			k = (struct libcuckoohash_key *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (libcuckoohash_cmp_eq(key, k->key, h) == 0) {
				if (data != NULL)
					*data = k->pdata;
				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}

	return -ENOENT;
}

int32_t
libcuckoohash_lookup_with_hash(const struct cuckoo_hash *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_lookup_with_hash(h, key, sig, NULL);
}

int32_t
libcuckoohash_lookup(const struct cuckoo_hash *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_lookup_with_hash(h, key, libcuckoohash_hash(h, key), NULL);
}

int
libcuckoohash_lookup_with_hash_data(const struct cuckoo_hash *h,
			const void *key, hash_sig_t sig, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_lookup_with_hash(h, key, sig, data);
}

int
libcuckoohash_lookup_data(const struct cuckoo_hash *h, const void *key, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_lookup_with_hash(h, key, libcuckoohash_hash(h, key), data);
}

static inline void
remove_entry(const struct cuckoo_hash *h, struct libcuckoohash_bucket *bkt, unsigned i)
{

	bkt->sig_current[i] = NULL_SIGNATURE;
	bkt->sig_alt[i] = NULL_SIGNATURE;
		libringbuf_sp_enqueue(h->free_slots,
				(void *)((uintptr_t)bkt->key_idx[i]));
}

static inline int32_t
__libcuckoohash_del_key_with_hash(const struct cuckoo_hash *h, const void *key,
						hash_sig_t sig)
{
	uint32_t bucket_idx;
	hash_sig_t alt_hash;
	unsigned i;
	struct libcuckoohash_bucket *bkt;
	struct libcuckoohash_key *k, *keys = h->key_store;
	int32_t ret;

	bucket_idx = sig & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in primary location */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig &&
				bkt->key_idx[i] != EMPTY_SLOT) {
			k = (struct libcuckoohash_key *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (libcuckoohash_cmp_eq(key, k->key, h) == 0) {
				remove_entry(h, bkt, i);

				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				ret = bkt->key_idx[i] - 1;
				bkt->key_idx[i] = EMPTY_SLOT;
				return ret;
			}
		}
	}

	/* Calculate secondary hash */
	alt_hash = libcuckoohash_secondary_hash(sig);
	bucket_idx = alt_hash & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in secondary location */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == alt_hash &&
				bkt->key_idx[i] != EMPTY_SLOT) {
			k = (struct libcuckoohash_key *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (libcuckoohash_cmp_eq(key, k->key, h) == 0) {
				remove_entry(h, bkt, i);

				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				ret = bkt->key_idx[i] - 1;
				bkt->key_idx[i] = EMPTY_SLOT;
				return ret;
			}
		}
	}

	return -ENOENT;
}

int32_t
libcuckoohash_del_key_with_hash(const struct cuckoo_hash *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_del_key_with_hash(h, key, sig);
}

int32_t
libcuckoohash_del_key(const struct cuckoo_hash *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __libcuckoohash_del_key_with_hash(h, key, libcuckoohash_hash(h, key));
}

int
libcuckoohash_get_key_with_position(const struct cuckoo_hash *h, const int32_t position,
			       void **key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	struct libcuckoohash_key *k, *keys = h->key_store;
	k = (struct libcuckoohash_key *) ((char *) keys + (position + 1) *
				     h->key_entry_size);
	*key = k->key;

	if (position !=
	    __libcuckoohash_lookup_with_hash(h, *key, libcuckoohash_hash(h, *key),
					NULL)) {
		return -ENOENT;
	}

	return 0;
}

static inline void
compare_signatures(uint32_t *prim_hash_matches, uint32_t *sec_hash_matches,
			const struct libcuckoohash_bucket *prim_bkt,
			const struct libcuckoohash_bucket *sec_bkt,
			hash_sig_t prim_hash, hash_sig_t sec_hash,
			enum libcuckoohash_sig_compare_function sig_cmp_fn)
{
	unsigned int i;

	switch (sig_cmp_fn) {
#ifdef RTE_MACHINE_CPUFLAG_AVX2
	case RTE_HASH_COMPARE_AVX2:
		*prim_hash_matches = _mm256_movemask_ps((__m256)_mm256_cmpeq_epi32(
				_mm256_load_si256(
					(__m256i const *)prim_bkt->sig_current),
				_mm256_set1_epi32(prim_hash)));
		*sec_hash_matches = _mm256_movemask_ps((__m256)_mm256_cmpeq_epi32(
				_mm256_load_si256(
					(__m256i const *)sec_bkt->sig_current),
				_mm256_set1_epi32(sec_hash)));
		break;
#endif
#ifdef RTE_MACHINE_CPUFLAG_SSE2
	case RTE_HASH_COMPARE_SSE:
		/* Compare the first 4 signatures in the bucket */
		*prim_hash_matches = _mm_movemask_ps((__m128)_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)prim_bkt->sig_current),
				_mm_set1_epi32(prim_hash)));
		*prim_hash_matches |= (_mm_movemask_ps((__m128)_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)&prim_bkt->sig_current[4]),
				_mm_set1_epi32(prim_hash)))) << 4;
		/* Compare the first 4 signatures in the bucket */
		*sec_hash_matches = _mm_movemask_ps((__m128)_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)sec_bkt->sig_current),
				_mm_set1_epi32(sec_hash)));
		*sec_hash_matches |= (_mm_movemask_ps((__m128)_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)&sec_bkt->sig_current[4]),
				_mm_set1_epi32(sec_hash)))) << 4;
		break;
#endif
	default:
		for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
			*prim_hash_matches |=
				((prim_hash == prim_bkt->sig_current[i]) << i);
			*sec_hash_matches |=
				((sec_hash == sec_bkt->sig_current[i]) << i);
		}
	}

}

#define PREFETCH_OFFSET 4

int32_t
libcuckoohash_iterate(const struct cuckoo_hash *h, const void **key, void **data, uint32_t *next)
{
	uint32_t bucket_idx, idx, position;
	struct libcuckoohash_key *next_key;

	RETURN_IF_TRUE(((h == NULL) || (next == NULL)), -EINVAL);

	const uint32_t total_entries = h->num_buckets * RTE_HASH_BUCKET_ENTRIES;
	/* Out of bounds */
	if (*next >= total_entries)
		return -ENOENT;

	/* Calculate bucket and index of current iterator */
	bucket_idx = *next / RTE_HASH_BUCKET_ENTRIES;
	idx = *next % RTE_HASH_BUCKET_ENTRIES;

	/* If current position is empty, go to the next one */
	while (h->buckets[bucket_idx].key_idx[idx] == EMPTY_SLOT) {
		(*next)++;
		/* End of table */
		if (*next == total_entries)
			return -ENOENT;
		bucket_idx = *next / RTE_HASH_BUCKET_ENTRIES;
		idx = *next % RTE_HASH_BUCKET_ENTRIES;
	}

	/* Get position of entry in key table */
	position = h->buckets[bucket_idx].key_idx[idx];
	next_key = (struct libcuckoohash_key *) ((char *)h->key_store +
				position * h->key_entry_size);
	/* Return key and data */
	*key = next_key->key;
	*data = next_key->pdata;

	/* Increment iterator */
	(*next)++;

	return position - 1;
}
