#ifndef _ZRAM_DEDUP_H_
#define _ZRAM_DEDUP_H_

struct zram;
struct zram_meta;
struct zram_entry;

#ifdef CONFIG_ZRAM_DEDUP
u64 zram_dedup_dup_size(struct zram *zram);
u64 zram_dedup_meta_size(struct zram *zram);

unsigned long zram_dedup_handle(struct zram *zram, struct zram_entry *entry);
void zram_dedup_insert(struct zram *zram, struct zram_entry *new,
				u32 checksum);
struct zram_entry *zram_dedup_find(struct zram *zram, unsigned char *mem,
				u32 *checksum);

struct zram_entry *zram_dedup_alloc(struct zram *zram,
			unsigned long handle, unsigned int len,
			gfp_t flags);
unsigned long zram_dedup_free(struct zram *zram, struct zram_meta *meta,
				struct zram_entry *entry);

int zram_dedup_init(struct zram *zram, struct zram_meta *meta,
				size_t num_pages);
void zram_dedup_fini(struct zram_meta *meta);
#else

static inline u64 zram_dedup_dup_size(struct zram *zram) { return 0; }
static inline u64 zram_dedup_meta_size(struct zram *zram) { return 0; }

static inline unsigned long zram_dedup_handle(struct zram *zram,
		struct zram_entry *entry) { return (unsigned long)entry; }
static inline void zram_dedup_insert(struct zram *zram, struct zram_entry *new,
		u32 checksum) { }
static inline struct zram_entry *zram_dedup_find(struct zram *zram,
		unsigned char *mem, u32 *checksum) { return NULL; }

static inline struct zram_entry *zram_dedup_alloc(struct zram *zram,
		unsigned long handle, unsigned int len, gfp_t flags)
{
	return (struct zram_entry *)handle;
}
static inline unsigned long zram_dedup_free(struct zram *zram,
		struct zram_meta *meta, struct zram_entry *entry)
{
	return (unsigned long)entry;
}

static inline int zram_dedup_init(struct zram *zram, struct zram_meta *meta,
		size_t num_pages) { return 0; }
void zram_dedup_fini(struct zram_meta *meta) { }

#endif

#endif /* _ZRAM_DEDUP_H_ */
