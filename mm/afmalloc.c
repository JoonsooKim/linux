/*
 * Anti Fragmentation Memory allocator
 *
 * Copyright (C) 2014 Joonsoo Kim
 *
 * Anti Fragmentation Memory allocator(aka afmalloc) is special purpose
 * allocator in order to deal with arbitrary sized object allocation
 * efficiently in terms of memory utilization.
 *
 * Overall design is too simple.
 *
 * If request is for power of 2 sized object, afmalloc allocate object
 * from the SLAB, add tag on it and return it to requestor. This tag will be
 * used for determining whether it is a handle for metadata or not.
 *
 * If request isn't for power of 2 sized object, afmalloc divides size
 * into elements in power of 2 size. For example, 400 byte request, 256,
 * 128, 16 bytes build up 400 bytes. afmalloc allocates these size memory
 * from the SLAB and allocates memory for metadata to keep the pointer of
 * these chunks. Conceptual representation of metadata structure is below.
 *
 * Metadata for 400 bytes
 * - Pointer for 256 bytes chunk
 * - Pointer for 128 bytes chunk
 * - Pointer for 16 bytes chunk
 *
 * After allocation all of them, afmalloc returns handle for this metadata to
 * requestor. Requestor can load/store from/into this memory via this handle.
 *
 * Returned memory from afmalloc isn't contiguous so using this memory needs
 * special APIs. afmalloc_(load/store) handles load/store requests according
 * to afmalloc's internal structure, so you can use it without any anxiety.
 *
 * If you may want to use this memory like as normal memory, you need to call
 * afmalloc_map_object before using it. This returns contiguous memory for
 * this handle so that you could use it with normal memory operation.
 * Unfortunately, only one object can be mapped per cpu at a time and to
 * contruct this mapping has some overhead.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/afmalloc.h>
#include <linux/highmem.h>
#include <linux/sizes.h>
#include <linux/module.h>

#define afmalloc_OBJ_MIN_SIZE (32)

#define DIRECT_ENTRY (0x1)

struct afmalloc_pool {
	spinlock_t lock;
	gfp_t flags;
	int max_level;
	size_t max_size;
	size_t size;
};

struct afmalloc_entry {
	int level;
	int alloced;
	void *mem[];
};

struct afmalloc_mapped_info {
	struct page *page;
	size_t len;
	bool read_only;
};

static struct afmalloc_mapped_info __percpu *mapped_info;

static struct afmalloc_entry *mem_to_direct_entry(void *mem)
{
	return (struct afmalloc_entry *)((unsigned long)mem | DIRECT_ENTRY);
}

static void *direct_entry_to_mem(struct afmalloc_entry *entry)
{
	return (void *)((unsigned long)entry & ~DIRECT_ENTRY);
}

static bool is_direct_entry(struct afmalloc_entry *entry)
{
	return (unsigned long)entry & DIRECT_ENTRY;
}

static unsigned long entry_to_handle(struct afmalloc_entry *entry)
{
	return (unsigned long)entry;
}

static struct afmalloc_entry *handle_to_entry(unsigned long handle)
{
	return (struct afmalloc_entry *)handle;
}

static bool valid_level(int max_level)
{
	if (max_level < AFMALLOC_MIN_LEVEL)
		return false;

	if (max_level > AFMALLOC_MAX_LEVEL)
		return false;

	return true;
}

static bool valid_flags(gfp_t flags)
{
	if (flags & __GFP_HIGHMEM)
		return false;

	return true;
}

/**
 * afmalloc_create_pool - Creates an allocation pool to work from.
 * @max_level: limit on number of chunks that is part of requested memory
 * @max_size: limit on total allocation size from this pool
 * @flags: allocation flags used to allocate memory
 *
 * This function must be called before anything when using
 * the afmalloc allocator.
 *
 * On success, a pointer to the newly created pool is returned,
 * otherwise NULL.
 */
struct afmalloc_pool *afmalloc_create_pool(int max_level, size_t max_size,
					gfp_t flags)
{
	struct afmalloc_pool *pool;

	if (!valid_level(max_level))
		return NULL;

	if (!valid_flags(flags))
		return NULL;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	spin_lock_init(&pool->lock);
	pool->flags = flags;
	pool->max_level = max_level;
	pool->max_size = max_size;
	pool->size = 0;

	return pool;
}
EXPORT_SYMBOL(afmalloc_create_pool);

void afmalloc_destroy_pool(struct afmalloc_pool *pool)
{
	kfree(pool);
}
EXPORT_SYMBOL(afmalloc_destroy_pool);

size_t afmalloc_get_used_pages(struct afmalloc_pool *pool)
{
	size_t size;

	spin_lock(&pool->lock);
	size = pool->size >> PAGE_SHIFT;
	spin_unlock(&pool->lock);

	return size;
}
EXPORT_SYMBOL(afmalloc_get_used_pages);

static void free_entry(struct afmalloc_pool *pool, struct afmalloc_entry *entry,
			bool calc_size)
{
	int i;
	int level;
	int alloced;

	if (is_direct_entry(entry)) {
		void *mem = direct_entry_to_mem(entry);

		alloced = ksize(mem);
		kfree(mem);
		goto out;
	}

	level = entry->level;
	alloced = entry->alloced;
	for (i = 0; i < level; i++)
		kfree(entry->mem[i]);

	kfree(entry);

out:
	if (calc_size && alloced) {
		spin_lock(&pool->lock);
		pool->size -= alloced;
		spin_unlock(&pool->lock);
	}
}

static int calculate_level(struct afmalloc_pool *pool, size_t len)
{
	int level = 0;
	size_t down_size, up_size;

	if (len <= afmalloc_OBJ_MIN_SIZE)
		goto out;

	while (1) {
		down_size = rounddown_pow_of_two(len);
		if (down_size >= len)
			break;

		up_size = roundup_pow_of_two(len);
		if (up_size - len <= afmalloc_OBJ_MIN_SIZE)
			break;

		len -= down_size;
		level++;
	}

out:
	level++;
	return min(level, pool->max_level);
}

static int estimate_alloced(struct afmalloc_pool *pool, int level, size_t len)
{
	int i, alloced = 0;
	size_t size;

	for (i = 0; i < level - 1; i++) {
		size = rounddown_pow_of_two(len);
		alloced += size;
		len -= size;
	}

	if (len < afmalloc_OBJ_MIN_SIZE)
		size = afmalloc_OBJ_MIN_SIZE;
	else
		size = roundup_pow_of_two(len);
	alloced += size;

	return alloced;
}

static void *alloc_entry(struct afmalloc_pool *pool, size_t len)
{
	int i, level;
	size_t size;
	int alloced = 0;
	size_t remain = len;
	struct afmalloc_entry *entry;
	void *mem;

	/*
	 * Determine whether memory is power of 2 or not. If not,
	 * determine how many chunks are needed.
	 */
	level = calculate_level(pool, len);
	if (level == 1)
		goto alloc_direct_entry;

	size = sizeof(void *) * level + sizeof(struct afmalloc_entry);
	entry = kmalloc(size, pool->flags);
	if (!entry)
		return NULL;

	size = ksize(entry);
	alloced += size;

	/*
	 * Although request isn't for power of 2 object, sometimes, it is
	 * better to allocate one power of 2 memory due to waste of metadata.
	 */
	if (size + estimate_alloced(pool, level, len)
				>= roundup_pow_of_two(len)) {
		kfree(entry);
		goto alloc_direct_entry;
	}

	entry->level = level;
	for (i = 0; i < level - 1; i++) {
		size = rounddown_pow_of_two(remain);
		entry->mem[i] = kmalloc(size, pool->flags);
		if (!entry->mem[i])
			goto err;

		alloced += size;
		remain -= size;
	}

	if (remain < afmalloc_OBJ_MIN_SIZE)
		size = afmalloc_OBJ_MIN_SIZE;
	else
		size = roundup_pow_of_two(remain);
	entry->mem[i] = kmalloc(size, pool->flags);
	if (!entry->mem[i])
		goto err;

	alloced += size;
	entry->alloced = alloced;
	goto alloc_complete;

alloc_direct_entry:
	mem = kmalloc(len, pool->flags);
	if (!mem)
		return NULL;

	alloced = ksize(mem);
	entry = mem_to_direct_entry(mem);

alloc_complete:
	spin_lock(&pool->lock);
	if (pool->size + alloced > pool->max_size) {
		spin_unlock(&pool->lock);
		goto err;
	}

	pool->size += alloced;
	spin_unlock(&pool->lock);

	return entry;

err:
	free_entry(pool, entry, false);

	return NULL;
}

static bool valid_alloc_arg(size_t len)
{
	if (!len)
		return false;

	return true;
}

/**
 * afmalloc_alloc - Allocate block of given length from pool
 * @pool: pool from which the object was allocated
 * @len: length of block to allocate
 *
 * On success, handle to the allocated object is returned,
 * otherwise 0.
 */
unsigned long afmalloc_alloc(struct afmalloc_pool *pool, size_t len)
{
	struct afmalloc_entry *entry;

	if (!valid_alloc_arg(len))
		return 0;

	entry = alloc_entry(pool, len);
	if (!entry)
		return 0;

	return entry_to_handle(entry);
}
EXPORT_SYMBOL(afmalloc_alloc);

static void __afmalloc_free(struct afmalloc_pool *pool,
			struct afmalloc_entry *entry)
{
	free_entry(pool, entry, true);
}

void afmalloc_free(struct afmalloc_pool *pool, unsigned long handle)
{
	struct afmalloc_entry *entry;

	entry = handle_to_entry(handle);
	if (!entry)
		return;

	__afmalloc_free(pool, entry);
}
EXPORT_SYMBOL(afmalloc_free);

static void __afmalloc_store(struct afmalloc_pool *pool,
			struct afmalloc_entry *entry, void *src, size_t len)
{
	int i, level = entry->level;
	size_t size;
	size_t offset = 0;

	if (is_direct_entry(entry)) {
		memcpy(direct_entry_to_mem(entry), src, len);
		return;
	}

	for (i = 0; i < level - 1; i++) {
		size = rounddown_pow_of_two(len);
		memcpy(entry->mem[i], src + offset, size);
		offset += size;
		len -= size;
	}
	memcpy(entry->mem[i], src + offset, len);
}

static bool valid_store_arg(struct afmalloc_entry *entry, void *src, size_t len)
{
	if (!entry)
		return false;

	if (!src || !len)
		return false;

	return true;
}

/**
 * afmalloc_store - store data into allocated object from handle.
 * @pool: pool from which the object was allocated
 * @handle: handle returned from afmalloc
 * @src: memory address of source data
 * @len: length in bytes of desired store
 *
 * To store data into an object allocated from afmalloc, it must be
 * mapped before using it or accessed through afmalloc-specific
 * load/store functions. These functions properly handle load/store
 * request according to afmalloc's internal structure.
 */
size_t afmalloc_store(struct afmalloc_pool *pool, unsigned long handle,
			void *src, size_t len)
{
	struct afmalloc_entry *entry;

	entry = handle_to_entry(handle);
	if (!valid_store_arg(entry, src, len))
		return 0;

	__afmalloc_store(pool, entry, src, len);

	return len;
}
EXPORT_SYMBOL(afmalloc_store);

static void __afmalloc_load(struct afmalloc_pool *pool,
			struct afmalloc_entry *entry, void *dst, size_t len)
{
	int i, level = entry->level;
	size_t size;
	size_t offset = 0;

	if (is_direct_entry(entry)) {
		memcpy(dst, direct_entry_to_mem(entry), len);
		return;
	}

	for (i = 0; i < level - 1; i++) {
		size = rounddown_pow_of_two(len);
		memcpy(dst + offset, entry->mem[i], size);
		offset += size;
		len -= size;
	}
	memcpy(dst + offset, entry->mem[i], len);
}

static bool valid_load_arg(struct afmalloc_entry *entry, void *dst, size_t len)
{
	if (!entry)
		return false;

	if (!dst || !len)
		return false;

	return true;
}

size_t afmalloc_load(struct afmalloc_pool *pool, unsigned long handle,
		void *dst, size_t len)
{
	struct afmalloc_entry *entry;

	entry = handle_to_entry(handle);
	if (!valid_load_arg(entry, dst, len))
		return 0;

	__afmalloc_load(pool, entry, dst, len);

	return len;
}
EXPORT_SYMBOL(afmalloc_load);

/**
 * afmalloc_map_object - get address of allocated object from handle.
 * @pool: pool from which the object was allocated
 * @handle: handle returned from afmalloc
 * @len: length in bytes of desired mapping
 * @read_only: flag that represents whether data on mapped region is
 *	written back into an object or not
 *
 * Before using an object allocated from afmalloc, it must be mapped using
 * this function. When done with the object, it must be unmapped using
 * afmalloc_unmap_handle.
 *
 * Only one object can be mapped per cpu at a time. There is no protection
 * against nested mappings.
 *
 * This function returns with preemption and page faults disabled.
 */
void *afmalloc_map_handle(struct afmalloc_pool *pool, unsigned long handle,
			size_t len, bool read_only)
{
	int cpu;
	struct afmalloc_entry *entry;
	struct afmalloc_mapped_info *info;
	void *addr;

	entry = handle_to_entry(handle);
	if (!entry)
		return NULL;

	cpu = get_cpu();
	if (is_direct_entry(entry))
		return direct_entry_to_mem(entry);

	info = per_cpu_ptr(mapped_info, cpu);
	addr = page_address(info->page);
	info->len = len;
	info->read_only = read_only;
	__afmalloc_load(pool, entry, addr, len);
	return addr;
}
EXPORT_SYMBOL(afmalloc_map_handle);

void afmalloc_unmap_handle(struct afmalloc_pool *pool, unsigned long handle)
{
	struct afmalloc_entry *entry;
	struct afmalloc_mapped_info *info;
	void *addr;

	entry = handle_to_entry(handle);
	if (!entry)
		return;

	if (is_direct_entry(entry))
		goto out;

	info = this_cpu_ptr(mapped_info);
	if (info->read_only)
		goto out;

	addr = page_address(info->page);
	__afmalloc_store(pool, entry, addr, info->len);

out:
	put_cpu();
}
EXPORT_SYMBOL(afmalloc_unmap_handle);

static int __init afmalloc_init(void)
{
	int cpu;

	mapped_info = alloc_percpu(struct afmalloc_mapped_info);
	if (!mapped_info)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct page *page;

		page = alloc_pages(GFP_KERNEL, 0);
		if (!page)
			goto err;

		per_cpu_ptr(mapped_info, cpu)->page = page;
	}

	return 0;

err:
	for_each_possible_cpu(cpu) {
		struct page *page;

		page = per_cpu_ptr(mapped_info, cpu)->page;
		if (page)
			__free_pages(page, 0);
	}
	free_percpu(mapped_info);
	return -ENOMEM;
}
module_init(afmalloc_init);

MODULE_AUTHOR("Joonsoo Kim <iamjoonsoo.kim@lge.com>");
