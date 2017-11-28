#ifndef __MM_KASAN_VCHECKER_H
#define __MM_KASAN_VCHECKER_H

struct vchecker;
struct vchecker_cb;

struct vchecker_cache {
	struct vchecker *checker;
	struct dentry *dir;
	int data_offset;
};


#ifdef CONFIG_VCHECKER
void vchecker_kmalloc(struct kmem_cache *s, const void *object, size_t size,
			unsigned long ret_ip);
bool vchecker_check(unsigned long addr, size_t size,
			bool write, unsigned long ret_ip);
int init_vchecker(struct kmem_cache *s);
void fini_vchecker(struct kmem_cache *s);
void vchecker_cache_create(struct kmem_cache *s, size_t *size,
			slab_flags_t *flags);
void vchecker_init_slab_obj(struct kmem_cache *s, const void *object);
void vchecker_enable_cache(struct kmem_cache *s, bool enable);
void vchecker_enable_obj(struct kmem_cache *s, const void *object,
			size_t size, bool enable);

#else
static inline void vchecker_kmalloc(struct kmem_cache *s,
	const void *object, size_t size, unsigned long ret_ip) { }
static inline bool vchecker_check(unsigned long addr, size_t size,
			bool write, unsigned long ret_ip) { return false; }
static inline int init_vchecker(struct kmem_cache *s) { return 0; }
static inline void fini_vchecker(struct kmem_cache *s) { }
static inline void vchecker_cache_create(struct kmem_cache *s,
			size_t *size, slab_flags_t *flags) {}
static inline void vchecker_init_slab_obj(struct kmem_cache *s,
	const void *object) {}

#endif


#endif
