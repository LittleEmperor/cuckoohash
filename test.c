
#include <stdlib.h>
#include <stdio.h>
#include "libcuckoohash.h"
#include "jhash.h"

struct libcuckoohash_parameters params = {
	.entries = (1<<18),
	.key_len = 16,
	.hash_func = NULL,
	.hash_func_init_val = RTE_JHASH_GOLDEN_RATIO
};
struct hash_entry{
	unsigned int val;
};

unsigned cnt = 0;
int g_pos[(1<<18)] = {0};

int main()
{
	int i;
	struct cuckoo_hash *h = libcuckoohash_create(&params);
	if(NULL == h){
		printf("create cuckooa_hash err\n");
		return -1;
	}
	struct hash_entry *entry = (struct hash_entry *)malloc((1<<18)*sizeof(struct hash_entry));
	if(NULL == entry){ 
		printf("create entry err\n");
		return -1;
	}

	for(i=0; i<(1<<17); i++){
		int pos = libcuckoohash_add_key(h, &i);
		if(pos < 0){
			printf("insert key err, key = %d\n", i);
			break;
		}
		entry[pos].val = i+1;
		g_pos[cnt] = pos;
		cnt++;
	}

	printf("insert all ok, cnt = %x\n", cnt);

	for(i=0; i<(int)cnt; i++){
		void *key;
		int ret = libcuckoohash_get_key_with_position(h, g_pos[i], &key);
		if(0 != ret){
			printf("get key err, cnt=%x, pos = %d\n", i, g_pos[i]);
			break;
		}
		
		ret = libcuckoohash_del_key(h, key);
		if(ret == g_pos[i]){
			printf("del key ok, cnt=%x, pos = %d, val=%u\n", i, g_pos[i], entry[ret].val);
		}else if(ret < 0){
			printf("del key err, cnt=%x, pos = %d\n", i, g_pos[i]);
			break;
		}else{
			printf("unknown err\n");
			break;
		}
	}
	printf("test finish\n");

	free(entry);
	libcuckoohash_free(h);
	return 0;
}

