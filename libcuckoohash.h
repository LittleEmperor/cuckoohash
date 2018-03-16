/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
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

#ifndef _RTE_HASH_H_
#define _RTE_HASH_H_

/**
 * @file
 *
 * RTE Hash Table
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size of hash table that can be created. */
#define RTE_HASH_ENTRIES_MAX			(1 << 27)

/** Signature of key that is stored internally. */
typedef uint32_t hash_sig_t;

/** Type of function that can be used for calculating the hash value. */
typedef uint32_t (*libcuckoohash_function)(const void *key, uint32_t key_len,
				      uint32_t init_val);

/** Type of function used to compare the hash key. */
typedef int (*libcuckoohash_cmp_eq_t)(const void *key1, const void *key2, size_t key_len);

/**
 * Parameters used when creating the hash table.
 */
struct libcuckoohash_parameters {
	uint32_t entries;		/**< Total hash table entries. */
	uint32_t key_len;		/**< Length of hash key. */
	libcuckoohash_function hash_func;	/**< Primary Hash function used to calculate hash. */
	uint32_t hash_func_init_val;	/**< Init value used by hash_func. */
};

/** @internal A hash table structure. */
struct cuckoo_hash;

/**
 * Create a new hash table.
 *
 * @param params
 *   Parameters used to create and initialise the hash table.
 * @return
 *   Pointer to hash table structure that is used in future hash table
 *   operations, or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - ENOENT - missing entry
 *    - EINVAL - invalid parameter passed to function
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
struct cuckoo_hash *
libcuckoohash_create(const struct libcuckoohash_parameters *params);

/**
 * Set a new hash compare function other than the default one.
 *
 * @note Function pointer does not work with multi-process, so do not use it
 * in multi-process mode.
 *
 * @param h
 *   Hash table for which the function is to be changed
 * @param func
 *   New compare function
 */
void libcuckoohash_set_cmp_func(struct cuckoo_hash *h, libcuckoohash_cmp_eq_t func);

/**
 * De-allocate all memory used by hash table.
 * @param h
 *   Hash table to free
 */
void
libcuckoohash_free(struct cuckoo_hash *h);

/**
 * Reset all hash structure, by zeroing all entries
 * @param h
 *   Hash table to reset
 */
void
libcuckoohash_reset(struct cuckoo_hash *h);

/**
 * Add a key-value pair to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param data
 *   Data to add to the hash table.
 * @return
 *   - 0 if added successfully
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 */
int
libcuckoohash_add_key_data(const struct cuckoo_hash *h, const void *key, void *data);

/*add by hzh*/
int
libcuckoohash_get_bucket_pos(const struct cuckoo_hash *h, hash_sig_t sig);

/**
 * Add a key-value pair with a pre-computed hash value
 * to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param sig
 *   Precomputed hash value for 'key'
 * @param data
 *   Data to add to the hash table.
 * @return
 *   - 0 if added successfully
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 */
int32_t
libcuckoohash_add_key_with_hash_data(const struct cuckoo_hash *h, const void *key,
						hash_sig_t sig, void *data);

/**
 * Add a key to an existing hash table. This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key.
 */
int32_t
libcuckoohash_add_key(const struct cuckoo_hash *h, const void *key);

/**
 * Add a key to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key.
 */
int32_t
libcuckoohash_add_key_with_hash(const struct cuckoo_hash *h, const void *key, hash_sig_t sig);

/**
 * Remove a key from an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
libcuckoohash_del_key(const struct cuckoo_hash *h, const void *key);

/**
 * Remove a key from an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
libcuckoohash_del_key_with_hash(const struct cuckoo_hash *h, const void *key, hash_sig_t sig);

/**
 * Find a key in the hash table given the position.
 * This operation is multi-thread safe.
 *
 * @param h
 *   Hash table to get the key from.
 * @param position
 *   Position returned when the key was inserted.
 * @param key
 *   Output containing a pointer to the key
 * @return
 *   - 0 if retrieved successfully
 *   - EINVAL if the parameters are invalid.
 *   - ENOENT if no valid key is found in the given position.
 */
int
libcuckoohash_get_key_with_position(const struct cuckoo_hash *h, const int32_t position,
			       void **key);

/**
 * Find a key-value pair in the hash table.
 * This operation is multi-thread safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param data
 *   Output with pointer to data returned from the hash table.
 * @return
 *   0 if successful lookup
 *   - EINVAL if the parameters are invalid.
 *   - ENOENT if the key is not found.
 */
int
libcuckoohash_lookup_data(const struct cuckoo_hash *h, const void *key, void **data);

/**
 * Find a key-value pair with a pre-computed hash value
 * to an existing hash table.
 * This operation is multi-thread safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param sig
 *   Precomputed hash value for 'key'
 * @param data
 *   Output with pointer to data returned from the hash table.
 * @return
 *   0 if successful lookup
 *   - EINVAL if the parameters are invalid.
 *   - ENOENT if the key is not found.
 */
int
libcuckoohash_lookup_with_hash_data(const struct cuckoo_hash *h, const void *key,
					hash_sig_t sig, void **data);

/**
 * Find a key in the hash table.
 * This operation is multi-thread safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
libcuckoohash_lookup(const struct cuckoo_hash *h, const void *key);

/**
 * Find a key in the hash table.
 * This operation is multi-thread safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param sig
 *   Hash value to remove from the hash table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
libcuckoohash_lookup_with_hash(const struct cuckoo_hash *h,
				const void *key, hash_sig_t sig);

/**
 * Calc a hash value by key.
 * This operation is not multi-thread safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @return
 *   - hash value
 */
hash_sig_t
libcuckoohash_hash(const struct cuckoo_hash *h, const void *key);

/**
 * Iterate through the hash table, returning key-value pairs.
 *
 * @param h
 *   Hash table to iterate
 * @param key
 *   Output containing the key where current iterator
 *   was pointing at
 * @param data
 *   Output containing the data associated with key.
 *   Returns NULL if data was not stored.
 * @param next
 *   Pointer to iterator. Should be 0 to start iterating the hash table.
 *   Iterator is incremented after each call of this function.
 * @return
 *   Position where key was stored, if successful.
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if end of the hash table.
 */
int32_t
libcuckoohash_iterate(const struct cuckoo_hash *h, const void **key, void **data, uint32_t *next);
#ifdef __cplusplus
}
#endif

#endif /* _RTE_HASH_H_ */
