#define AFMALLOC_MIN_LEVEL (1)
#ifdef CONFIG_64BIT
#define AFMALLOC_MAX_LEVEL (7)	/* 4 + 4 + 8 * 7 = 64 */
#else
#define AFMALLOC_MAX_LEVEL (6)	/* 4 + 4 + 4 * 6 = 32 */
#endif

extern struct afmalloc_pool *afmalloc_create_pool(int max_level,
			size_t max_size, gfp_t flags);
extern void afmalloc_destroy_pool(struct afmalloc_pool *pool);
extern size_t afmalloc_get_used_pages(struct afmalloc_pool *pool);
extern unsigned long afmalloc_alloc(struct afmalloc_pool *pool, size_t len);
extern void afmalloc_free(struct afmalloc_pool *pool, unsigned long handle);
extern size_t afmalloc_store(struct afmalloc_pool *pool, unsigned long handle,
			void *src, size_t len);
extern size_t afmalloc_load(struct afmalloc_pool *pool, unsigned long handle,
			void *dst, size_t len);
extern void *afmalloc_map_handle(struct afmalloc_pool *pool,
			unsigned long handle, size_t len, bool read_only);
extern void afmalloc_unmap_handle(struct afmalloc_pool *pool,
			unsigned long handle);
