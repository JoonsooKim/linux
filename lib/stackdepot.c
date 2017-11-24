/*
 * Generic stack depot for storing stack traces.
 *
 * Some debugging tools need to save stack traces of certain events which can
 * be later presented to the user. For example, KASAN needs to safe alloc and
 * free stacks for each object, but storing two stack traces per object
 * requires too much memory (e.g. SLUB_DEBUG needs 256 bytes per object for
 * that).
 *
 * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
 * and free stacks repeat a lot, we save about 100x space.
 * Stacks are never removed from depot, so we store them contiguously one after
 * another in a contiguos memory allocation.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on code by Dmitry Chernenkov.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)

#define STACK_ALLOC_NULL_PROTECTION_BITS 1
#define STACK_ALLOC_ORDER 2 /* 'Slab' size order for stack depot, 4 pages */
#define STACK_ALLOC_SIZE (1LL << (PAGE_SHIFT + STACK_ALLOC_ORDER))
#define STACK_ALLOC_ALIGN 4
#define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
					STACK_ALLOC_ALIGN)
#define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
		STACK_ALLOC_NULL_PROTECTION_BITS - STACK_ALLOC_OFFSET_BITS)
#define STACK_ALLOC_SLABS_CAP 8192
#define STACK_ALLOC_MAX_SLABS \
	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
	 (1LL << (STACK_ALLOC_INDEX_BITS)) : STACK_ALLOC_SLABS_CAP)

#define STACK_HASH_ORDER 20
#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
#define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
#define STACK_HASH_SEED 0x9747b28c

/* The compact structure to store the reference to stacks. */
union handle_parts {
	depot_stack_handle_t handle;
	struct {
		u32 slabindex : STACK_ALLOC_INDEX_BITS;
		u32 offset : STACK_ALLOC_OFFSET_BITS;
		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
	};
};

struct stack_record {
	struct stack_record *next;	/* Link in the hashtable */
	u32 hash;			/* Hash in the hastable */
	u32 size;			/* Number of frames in the stack */
	union handle_parts handle;
	unsigned long entries[1];	/* Variable-sized array of entries. */
};

struct stackdepot {
	spinlock_t lock;
	int depot_index;
	int next_slab_inited;
	size_t depot_offset;

	void *stack_slabs[STACK_ALLOC_MAX_SLABS];
	struct stack_record *stack_table[STACK_HASH_SIZE];
};

static struct stackdepot global_stackdepot = {
	.lock	= __SPIN_LOCK_UNLOCKED(global_stackdepot.lock),
};

static bool init_stack_slab(struct stackdepot *s, void **prealloc)
{
	if (!*prealloc)
		return false;
	/*
	 * This smp_load_acquire() pairs with smp_store_release() to
	 * |next_slab_inited| below and in depot_alloc_stack().
	 */
	if (smp_load_acquire(&s->next_slab_inited))
		return true;
	if (s->stack_slabs[s->depot_index] == NULL) {
		s->stack_slabs[s->depot_index] = *prealloc;
	} else {
		s->stack_slabs[s->depot_index + 1] = *prealloc;
		/*
		 * This smp_store_release pairs with smp_load_acquire() from
		 * |next_slab_inited| above and in depot_save_stack().
		 */
		smp_store_release(&s->next_slab_inited, 1);
	}
	*prealloc = NULL;
	return true;
}

/* Allocation of a new stack in raw storage */
static struct stack_record *depot_alloc_stack(struct stackdepot *s,
		unsigned long *entries, int size,
		u32 hash, void **prealloc, gfp_t alloc_flags)
{
	int required_size = offsetof(struct stack_record, entries) +
		sizeof(unsigned long) * size;
	struct stack_record *stack;

	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);

	if (unlikely(s->depot_offset + required_size > STACK_ALLOC_SIZE)) {
		if (unlikely(s->depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
			WARN_ONCE(1, "Stack depot reached limit capacity");
			return NULL;
		}
		s->depot_index++;
		s->depot_offset = 0;
		/*
		 * smp_store_release() here pairs with smp_load_acquire() from
		 * |next_slab_inited| in depot_save_stack() and
		 * init_stack_slab().
		 */
		if (s->depot_index + 1 < STACK_ALLOC_MAX_SLABS)
			smp_store_release(&s->next_slab_inited, 0);
	}
	init_stack_slab(s, prealloc);
	if (s->stack_slabs[s->depot_index] == NULL) {
		if (!(alloc_flags & __GFP_NOWARN))
			WARN_ONCE(1, "Stack depot failed to allocate stack_slabs");
		return NULL;
	}

	stack = s->stack_slabs[s->depot_index] + s->depot_offset;

	stack->hash = hash;
	stack->size = size;
	stack->handle.slabindex = s->depot_index;
	stack->handle.offset = s->depot_offset >> STACK_ALLOC_ALIGN;
	stack->handle.valid = 1;
	memcpy(stack->entries, entries, size * sizeof(unsigned long));
	s->depot_offset += required_size;

	return stack;
}

/* Calculate hash for a stack */
static inline u32 hash_stack(unsigned long *entries, unsigned int size)
{
	return jhash2((u32 *)entries,
			       size * sizeof(unsigned long) / sizeof(u32),
			       STACK_HASH_SEED);
}

/* Find a stack that is equal to the one stored in entries in the hash */
static inline struct stack_record *find_stack(struct stack_record *bucket,
					     unsigned long *entries, int size,
					     u32 hash)
{
	struct stack_record *found;

	for (found = bucket; found; found = found->next) {
		if (found->hash == hash &&
		    found->size == size &&
		    !memcmp(entries, found->entries,
			    size * sizeof(unsigned long))) {
			return found;
		}
	}
	return NULL;
}

void depot_fetch_stack(struct stackdepot *s,
		depot_stack_handle_t handle, struct stack_trace *trace)
{
	union handle_parts parts = { .handle = handle };
	struct stackdepot *s2 = s ? : &global_stackdepot;
	void *slab = s2->stack_slabs[parts.slabindex];
	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
	struct stack_record *stack = slab + offset;

	trace->nr_entries = trace->max_entries = stack->size;
	trace->entries = stack->entries;
	trace->skip = 0;
}
EXPORT_SYMBOL_GPL(depot_fetch_stack);

/**
 * depot_save_stack - save stack in a stack depot.
 * @trace - the stacktrace to save.
 * @alloc_flags - flags for allocating additional memory if required.
 * @is_new - set #true when @trace was not in the stack depot.
 *
 * Returns the handle of the stack struct stored in depot.
 */
depot_stack_handle_t depot_save_stack(struct stackdepot *s,
		struct stack_trace *trace, gfp_t alloc_flags, bool *is_new)
{
	u32 hash;
	depot_stack_handle_t retval = 0;
	struct stack_record *found = NULL, **bucket;
	unsigned long flags;
	struct page *page = NULL;
	void *prealloc = NULL;

	if (unlikely(trace->nr_entries == 0))
		goto fast_exit;

	if (!s)
		s = &global_stackdepot;

	hash = hash_stack(trace->entries, trace->nr_entries);
	bucket = &s->stack_table[hash & STACK_HASH_MASK];

	/*
	 * Fast path: look the stack trace up without locking.
	 * The smp_load_acquire() here pairs with smp_store_release() to
	 * |bucket| below.
	 */
	found = find_stack(smp_load_acquire(bucket), trace->entries,
			   trace->nr_entries, hash);
	if (found)
		goto exit;

	/*
	 * Check if the current or the next stack slab need to be initialized.
	 * If so, allocate the memory - we won't be able to do that under the
	 * lock.
	 *
	 * The smp_load_acquire() here pairs with smp_store_release() to
	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
	 */
	if (unlikely(!smp_load_acquire(&s->next_slab_inited))) {
		gfp_t orig_flags = alloc_flags;

		/*
		 * Zero out zone modifiers, as we don't have specific zone
		 * requirements. Keep the flags related to allocation in atomic
		 * contexts and I/O.
		 */
		alloc_flags &= ~GFP_ZONEMASK;
		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
		alloc_flags |= __GFP_NOWARN;
		page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);
		if (page)
			prealloc = page_address(page);

		/* restore flags to report failure in depot_alloc_stack() */
		alloc_flags = orig_flags;
	}

	spin_lock_irqsave(&s->lock, flags);

	found = find_stack(*bucket, trace->entries, trace->nr_entries, hash);
	if (!found) {
		struct stack_record *new =
			depot_alloc_stack(s, trace->entries, trace->nr_entries,
					  hash, &prealloc, alloc_flags);
		if (new) {
			new->next = *bucket;
			/*
			 * This smp_store_release() pairs with
			 * smp_load_acquire() from |bucket| above.
			 */
			smp_store_release(bucket, new);
			found = new;
			if (is_new)
				*is_new = true;
		}
	} else if (prealloc) {
		/*
		 * We didn't need to store this stack trace, but let's keep
		 * the preallocated memory for the future.
		 */
		WARN_ON(!init_stack_slab(s, &prealloc));
	}

	spin_unlock_irqrestore(&s->lock, flags);
exit:
	if (prealloc) {
		/* Nobody used this memory, ok to free it. */
		free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
	}
	if (found)
		retval = found->handle.handle;
fast_exit:
	return retval;
}
EXPORT_SYMBOL_GPL(depot_save_stack);

struct stackdepot *create_stackdepot(void)
{
	struct stackdepot *s;

	s = vzalloc(sizeof(*s));
	if (!s)
		return NULL;

	spin_lock_init(&s->lock);
	return s;
}
EXPORT_SYMBOL_GPL(create_stackdepot);

void destroy_stackdepot(struct stackdepot *s)
{
	vfree(s);
}
EXPORT_SYMBOL_GPL(destroy_stackdepot);
