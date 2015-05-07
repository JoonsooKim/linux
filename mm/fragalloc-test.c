#define pr_fmt(fmt) "fragalloc_test: " fmt
#define DEBUG

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/random.h>

static u64 free_percent = 10;
static gfp_t gfp_flags = GFP_HIGHUSER;
static unsigned long alloc_count = 0;
static LIST_HEAD(alloced_pages);

static void run_alloc(void)
{
	unsigned int index;
	struct page *page;
	unsigned long free_count = 0;

	/* Phase 1. Alloc */
	while (true) {
		page = alloc_pages(gfp_flags | __GFP_NOWARN | __GFP_NORETRY, 0);
		if (!page)
			break;

		__SetPageSlab(page);
		list_add_tail(&page->lru, &alloced_pages);
		alloc_count++;
	}
	pr_debug("%s: %lu pages alloced\n", __func__, alloc_count);

	/* Phase 2. Free */
	free_count = alloc_count * free_percent / 100;
	free_count = min (alloc_count, free_count);
	pr_debug("%s: %lu pages will be freed\n", __func__, free_count);

	while (free_count--) {
		index = get_random_int() % pageblock_nr_pages;

		while (index--) {
			list_rotate_left(&alloced_pages);
		}
		page = list_first_entry(&alloced_pages, struct page, lru);
		list_del(&page->lru);
		alloc_count--;
		__ClearPageSlab(page);
		__free_pages(page, 0);
	}

	pr_debug("%s: %lu pages remained\n", __func__, alloc_count);
}

static void run_free(void)
{
	struct page *page;

	while (!list_empty(&alloced_pages)) {
		page = list_first_entry(&alloced_pages, struct page, lru);
		list_del(&page->lru);
		alloc_count--;
		__ClearPageSlab(page);
		__free_pages(page, 0);
	}

	pr_debug("%s: %lu pages remained\n", __func__, alloc_count);
}

#ifdef CONFIG_DEBUG_FS
static int fragalloc_alloc(void *data, u64 val)
{
	run_alloc();

	return 0;
}

static int fragalloc_free(void *data, u64 val)
{
	run_free();

	return 0;
}

static int gfp_flags_store(void *data, u64 val)
{
	if (val != GFP_HIGHUSER && val != GFP_HIGHUSER_MOVABLE)
		return -EINVAL;

	gfp_flags = (gfp_t)val;
	return 0;
}

static int gfp_flags_show(void *data, u64 *val)
{
	*val = (u64)gfp_flags;

	pr_debug("current: 0x%lx\n", (unsigned long)*val);
	pr_debug("possible-1: 0x%lx\n", (unsigned long)GFP_HIGHUSER);
	pr_debug("possible-2: 0x%lx\n", (unsigned long)GFP_HIGHUSER_MOVABLE);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fragalloc_alloc_fops, NULL, fragalloc_alloc, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(fragalloc_free_fops, NULL, fragalloc_free, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(gfp_flags_fops, gfp_flags_show, gfp_flags_store, "0x%llx\n");

static int __init fragalloc_test_debugfs_init(void)
{
	struct dentry *root;

	root = debugfs_create_dir("fragalloc-test", NULL);
	if (root == NULL)
		return -ENXIO;

	debugfs_create_file("alloc", 0200, root, NULL, &fragalloc_alloc_fops);
	debugfs_create_file("free", 0200, root, NULL, &fragalloc_free_fops);
	debugfs_create_u64("free_percent", 0644, root, &free_percent);
	debugfs_create_file("gfp_flags", 0644, root, NULL, &gfp_flags_fops);

	return 0;
}
#else
static int __init fragalloc_test_debugfs_init(void) { return 0; }
#endif

static int fragalloc_test_init(void)
{
	return fragalloc_test_debugfs_init();
}

static void fragalloc_test_exit(void)
{
}

module_init(fragalloc_test_init);
module_exit(fragalloc_test_exit);

MODULE_AUTHOR("Joonsoo Kim <iamjoonsoo.kim@lge.com>");
MODULE_LICENSE("GPL");
