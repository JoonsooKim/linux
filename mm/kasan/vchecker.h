#ifndef __MM_KASAN_VCHECKER_H
#define __MM_KASAN_VCHECKER_H

struct vchecker;
struct vchecker_cb;

struct vchecker_cache {
	struct vchecker *checker;
	struct dentry *dir;
};


#ifdef CONFIG_VCHECKER
void vchecker_kmalloc(struct kmem_cache *s, const void *object, size_t size);
bool vchecker_check(unsigned long addr, size_t size,
			bool write, unsigned long ret_ip);
int init_vchecker(struct kmem_cache *s);
void fini_vchecker(struct kmem_cache *s);

#else
static inline void vchecker_kmalloc(struct kmem_cache *s,
	const void *object, size_t size) { }
static inline bool vchecker_check(unsigned long addr, size_t size,
			bool write, unsigned long ret_ip) { return false; }
static inline int init_vchecker(struct kmem_cache *s) { return 0; }
static inline void fini_vchecker(struct kmem_cache *s) { }

#endif


#endif
