/*
 * CMA DebugFS Interface
 *
 * Copyright (c) 2015 Sasha Levin <sasha.levin@oracle.com>
 */
 

#include <linux/debugfs.h>
#include <linux/cma.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/dma-contiguous.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/sizes.h>

#include "cma.h"

struct cma_mem {
	struct hlist_node node;
	struct page *p;
	unsigned long n;
};

static HLIST_HEAD(cma_mem_head);
static DEFINE_SPINLOCK(cma_mem_head_lock);

static struct dentry *cma_debugfs_root;

static bool reserve_areas;
static int __init early_test_cma_areas(char *buf)
{
	if (!buf)
		return -EINVAL;

	if (strcmp(buf, "on") == 0)
		reserve_areas = true;

	return 0;
}
early_param("cma_test_areas", early_test_cma_areas);

void reserve_test_cma_areas(void)
{
	struct cma *cma;

	if (!reserve_areas)
		return;

	cma_declare_contiguous(0, SZ_64M, 0, 0, 0, false, &cma);
	cma_declare_contiguous(0, SZ_128M, cma_get_base(cma) -
				SZ_128M - SZ_64M, 0, 1, false, &cma);
	cma_declare_contiguous(0, SZ_256M, 0, SZ_256M, 3, false, &cma);
}

static int cma_debugfs_get(void *data, u64 *val)
{
	unsigned long *p = data;

	*val = *p;

	return 0;
} 

static void cma_add_to_cma_mem_list(struct cma_mem *mem)
{
	spin_lock(&cma_mem_head_lock);
	hlist_add_head(&mem->node, &cma_mem_head);
	spin_unlock(&cma_mem_head_lock);
}

static int cma_alloc_mem(struct cma *cma, int count)
{
	struct cma_mem *mem;
	struct page *p;

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	p = cma_alloc(cma, count, get_order(count << PAGE_SHIFT));
	if (!p) {
		kfree(mem);
		return -ENOMEM;
	}

	mem->p = p;
	mem->n = count;

	cma_add_to_cma_mem_list(mem);

	return 0;
}

static int cma_alloc_write(void *data, u64 val)
{
	struct cma *cma = (struct cma *)data;
	int pages = val;

	return cma_alloc_mem(cma, pages);
}

static struct cma_mem *cma_get_entry_from_list(void)
{
	struct cma_mem *mem = NULL;

	spin_lock(&cma_mem_head_lock);
	if (!hlist_empty(&cma_mem_head)) {
		mem = hlist_entry(cma_mem_head.first, struct cma_mem, node);
		hlist_del_init(&mem->node);
	}
	spin_unlock(&cma_mem_head_lock);

	return mem;
}

static int cma_free_mem(struct cma *cma, int count)
{
	struct cma_mem *mem = NULL;

	while (count) {
		mem = cma_get_entry_from_list();
		if (mem == NULL)
			return 0;

		if (mem->n <= count) {
			cma_release(cma, mem->p, mem->n);
			count -= mem->n;
			kfree(mem);
		} else {
			cma_release(cma, mem->p, count);
			mem->p += count;
			mem->n -= count;
			count = 0;
			cma_add_to_cma_mem_list(mem);
		}
	}

	return 0;
}

static int cma_free_write(void *data, u64 val)
{
	struct cma *cma = (struct cma *)data;
        int pages = val;

        return cma_free_mem(cma, pages);
}


DEFINE_SIMPLE_ATTRIBUTE(cma_debugfs_fops, cma_debugfs_get, NULL, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(cma_alloc_fops, NULL, cma_alloc_write, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(cma_free_fops, NULL, cma_free_write, "%llu\n");

static void cma_debugfs_add_one(struct cma *cma, int idx)
{
	struct dentry *tmp;
	char name[16];
	int u32s;

	sprintf(name, "cma-%d", idx);

	tmp = debugfs_create_dir(name, cma_debugfs_root);

	debugfs_create_file("base_pfn", S_IRUGO, tmp,
				&cma->base_pfn, &cma_debugfs_fops);
	debugfs_create_file("count", S_IRUGO, tmp,
				&cma->count, &cma_debugfs_fops);
	debugfs_create_file("order_per_bit", S_IRUGO, tmp,
			&cma->order_per_bit, &cma_debugfs_fops);
	debugfs_create_file("alloc", S_IWUSR, tmp,
				cma, &cma_alloc_fops);
	debugfs_create_file("free", S_IWUSR, tmp,
				cma, &cma_free_fops);

	u32s = DIV_ROUND_UP(cma_bitmap_maxno(cma), BITS_PER_BYTE * sizeof(u32));
	debugfs_create_u32_array("bitmap", S_IRUGO, tmp, (u32*)cma->bitmap, u32s);
}

static int __init cma_debugfs_init(void)
{
	int i;

	cma_debugfs_root = debugfs_create_dir("cma", NULL);
	if (!cma_debugfs_root)
		return -ENOMEM;

	for (i = 0; i < cma_area_count; i++)
		cma_debugfs_add_one(&cma_areas[i], i);

	return 0;
}
late_initcall(cma_debugfs_init);

