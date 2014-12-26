#define pr_fmt(fmt) "fragmentation_test: " fmt
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
#include <linux/sort.h>

static u64 msdelay = 100;
static u64 batch_pages = 1;
static u64 batch_count = 128;
static u64 check_interval = 32;
static u64 order = 0;
static gfp_t gfp_flags = GFP_KERNEL;

static int pfn_cmp(const void *a, const void *b)
{
	struct page *pa = *(struct page **)a, *pb = *(struct page **)b;
	unsigned long pfna, pfnb;

	pfna = page_to_pfn(pa);
	pfnb = page_to_pfn(pb);
	if (pfna > pfnb)
		return 1;
	else if (pfna == pfnb)
		return 0;
	else
		return -1;
}

static unsigned long get_nr_pageblock(struct page **pages, struct page **sorted, unsigned long entries)
{
	unsigned long i;
	bool check_start = false;
	unsigned long nr_pageblock = 0;
	unsigned long pfn, prev_pfn;

	memcpy(sorted, pages, sizeof(struct page *) * entries);
	sort(sorted, entries, sizeof(struct page *), pfn_cmp, NULL);

	for (i = 0; i < entries; i++) {
		pfn = page_to_pfn(sorted[i]);

		if (check_start) {
			if (ALIGN(prev_pfn, pageblock_nr_pages) ==
				ALIGN(pfn, pageblock_nr_pages))
				continue;
		}

		check_start = true;
		prev_pfn = pfn;
		nr_pageblock++;
	}

	return nr_pageblock;
}

static void runtest(unsigned int order, unsigned long batch_pages,
	unsigned long batch_count, gfp_t gfp_flags, unsigned long msdelay,
	unsigned long check_interval)
{
	int i;
	struct page **pages = NULL;	/* Pages that were allocated */
	struct page **sorted = NULL;	/* Pages that were sorted by pfn */
	unsigned long numpages = batch_pages * batch_count;
	unsigned long alloced=0;
	unsigned long attempts=0;
	unsigned long nextjiffies = jiffies;
	unsigned long lastjiffies = jiffies;
	unsigned long min_nr_pageblock;
	unsigned long *nr_pageblocks = NULL;

	/* Check parameters */
	if (order < 0 || order >= MAX_ORDER) {
		pr_debug("Order request of %u makes no sense\n", order);
		return;
	}

	if (numpages < 0) {
		pr_debug("Number of pages %lu makes no sense\n", numpages);
		return;
	}

	/*
	 * Allocate memory to store pointers to pages.
	 */
	pages = vzalloc(numpages * sizeof(struct page *));
	sorted = vzalloc(numpages * sizeof(struct page *));
	nr_pageblocks = vzalloc(numpages * sizeof(unsigned long));
	if (pages == NULL || sorted == NULL || nr_pageblocks == NULL) {
		pr_debug("Failed to allocate space to store page pointers\n");
		goto free;
	}

#if defined(OOM_DISABLE)
	/* Disable OOM Killer */
	pr_debug("Disabling OOM killer for running process\n");
	oomkilladj = current->oomkilladj;
	current->oomkilladj = OOM_DISABLE;
#endif /* OOM_DISABLE */

	/*
	 * Attempt to allocate the requested number of pages
	 */
	while (attempts != batch_count) {
		if (lastjiffies > jiffies)
			nextjiffies = jiffies;

		/* What the hell is this, should be a waitqueue */
		while (jiffies < nextjiffies) {
			__set_current_state(TASK_RUNNING);
			schedule();
		}
		nextjiffies = jiffies + ( (HZ * msdelay)/1000);

		/* Print message if this is taking a long time */
		if (jiffies - lastjiffies > HZ) {
			pr_debug("fragmentation alloc test attempts: %lu\n",
					attempts);
		}

		/* Print out a message every so often anyway */
		if (attempts > 0 && attempts % 10 == 0) {
			pr_debug("High order alloc test attempts: %lu\n",
					attempts);
		}

		lastjiffies = jiffies;

		for (i = 0; i < batch_pages; i++) {
			pages[alloced] = alloc_pages(gfp_flags, order);
			if (pages[alloced] == NULL)
				goto out;

			alloced++;
		}

		attempts++;
	}

out:

	/* Re-enable OOM Killer state */
#ifdef OOM_DISABLED
	pr_debug("Re-enabling OOM Killer status\n");
	current->oomkilladj = oomkilladj;
#endif

	if (alloced != numpages)
		goto free;

	for (i = 0; i < alloced; i++) {
		if (i % check_interval == 0 || i == (alloced - 1))
			nr_pageblocks[i] = get_nr_pageblock(pages, sorted, i + 1);
	}

	min_nr_pageblock = DIV_ROUND_UP(numpages, pageblock_nr_pages);
	pr_debug("Test completed with %lu allocs, printing results\n", alloced);

	pr_debug("Order:                         %u\n", order);
	pr_debug("GFP flags:                     0x%lx\n", (unsigned long)gfp_flags);
	pr_debug("Attempted allocations:         %lu\n", numpages);
	pr_debug("Batch pages:                   %lu\n", batch_pages);
	pr_debug("Delay on each batch pages(ms): %lu\n", msdelay);
	pr_debug("Check interval(pages):         %lu\n", check_interval);
	pr_debug("Minimum Pageblocks:            %lu\n", min_nr_pageblock);
	pr_debug("Final Pageblocks:              %lu\n", nr_pageblocks[alloced - 1]);
	pr_debug("Final Ratio:                   %lu\n", DIV_ROUND_UP(nr_pageblocks[alloced - 1], min_nr_pageblock));
	pr_debug("Number of Pageblocks:\n");
	for (i = 0; i < alloced; i++) {
		if (i % check_interval == 0)
			pr_debug("%d: %lu\n", i, nr_pageblocks[i]);
	}

free:
	/*
	 * Free up the pages
	 */
	for (i = 0; i < alloced; i++)
		__free_pages(pages[i], order);

	vfree(pages);
	vfree(sorted);
	vfree(nr_pageblocks);

	return;
}

#ifdef CONFIG_DEBUG_FS
static int runtest_store(void *data, u64 val)
{
	runtest(order, batch_pages, batch_count,
		gfp_flags, msdelay, check_interval);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(runtest_fops, NULL, runtest_store, "%llu\n");

static int __init fragmentation_test_debugfs_init(void)
{
	struct dentry *root;

	root = debugfs_create_dir("fragmentation-test", NULL);
	if (root == NULL)
		return -ENXIO;

	debugfs_create_file("runtest", 0200, root, NULL, &runtest_fops);
	debugfs_create_u64("msdelay", 0644, root, &msdelay);
	debugfs_create_u64("batch_pages", 0644, root, &batch_pages);
	debugfs_create_u64("batch_count", 0644, root, &batch_count);
	debugfs_create_u64("order", 0644, root, &order);
	debugfs_create_u64("check_interval", 0644, root, &check_interval);

	return 0;
}
#else
static int __init highalloc_test_debugfs_init(void) { return 0; }
#endif

static int fragmentation_test_init(void)
{
	return fragmentation_test_debugfs_init();
}

static void fragmentation_test_exit(void)
{
}

module_init(fragmentation_test_init);
module_exit(fragmentation_test_exit);

MODULE_AUTHOR("Joonsoo Kim <iamjoonsoo.kim@lge.com>");
MODULE_LICENSE("GPL");
