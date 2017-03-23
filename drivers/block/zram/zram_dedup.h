#ifndef _ZRAM_DEDUP_H_
#define _ZRAM_DEDUP_H_

struct zram;
struct zram_meta;
struct zram_entry;

u64 zram_dedup_dup_size(struct zram *zram);
u64 zram_dedup_meta_size(struct zram *zram);

void zram_dedup_insert(struct zram *zram, struct zram_entry *new,
				u32 checksum);
struct zram_entry *zram_dedup_find(struct zram *zram, unsigned char *mem,
				u32 *checksum);

struct zram_entry *zram_dedup_alloc(struct zram *zram,
				unsigned long handle, gfp_t flags);
unsigned long zram_dedup_free(struct zram *zram, struct zram_entry *entry);

int zram_dedup_init(struct zram_meta *meta, size_t num_pages);
void zram_dedup_fini(struct zram_meta *meta);

#endif /* _ZRAM_DEDUP_H_ */
