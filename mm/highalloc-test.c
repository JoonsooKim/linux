#define pr_fmt(fmt) "highalloc_test: " fmt
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

static u64 msdelay = 100;
static u64 count = 100;
static u64 order = 5;
static gfp_t gfp_flags = GFP_HIGHUSER;

static void runtest(unsigned int order, unsigned long numpages,
			gfp_t gfp_flags, unsigned long msdelay)
{
	struct page **pages = NULL;	/* Pages that were allocated */
	unsigned long attempts=0, printed=0;
	unsigned long alloced=0;
	unsigned long nextjiffies = jiffies;
	unsigned long lastjiffies = jiffies;
	unsigned long success=0;
	unsigned long fail=0;
	unsigned long aborted=0;
	unsigned long page_dma=0, page_dma32=0, page_normal=0, page_highmem=0, page_easyrclm=0;
	struct zone *zone;
	char finishString[60];
	bool enabled_preempt = false;
	ktime_t start_ktime;
	ktime_t * alloc_latencies = NULL;
	bool * alloc_outcomes = NULL;

	/* Check parameters */
	if (order < 0 || order >= MAX_ORDER) {
		pr_debug("Order request of %u makes no sense\n", order);
		goto out_preempt;
	}

	if (numpages < 0) {
		pr_debug("Number of pages %lu makes no sense\n", numpages);
		goto out_preempt;
	}

	if (in_atomic()) {
		pr_debug("WARNING: Enabling preempt behind systemtaps back\n");
		preempt_enable();
		enabled_preempt = true;
	}

	/*
	 * Allocate memory to store pointers to pages.
	 */
	pages = __vmalloc((numpages+1) * sizeof(struct page **),
			GFP_KERNEL|__GFP_HIGHMEM,
			PAGE_KERNEL);
	if (pages == NULL) {
		pr_debug("Failed to allocate space to store page pointers\n");
		goto out_preempt;
	}
	/*
	 * Allocate arrays for storing allocation outcomes and latencies
	 */
	alloc_latencies = __vmalloc((numpages+1) * sizeof(ktime_t),
			GFP_KERNEL|__GFP_HIGHMEM,
			PAGE_KERNEL);
	if (alloc_latencies == NULL) {
		pr_debug("Failed to allocate space to store allocation latencies\n");
		goto out_preempt;
	}
	alloc_outcomes = __vmalloc((numpages+1) * sizeof(bool),
			GFP_KERNEL|__GFP_HIGHMEM,
			PAGE_KERNEL);
	if (alloc_outcomes == NULL) {
		pr_debug("Failed to allocate space to store allocation outcomes\n");
		goto out_preempt;
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
	while (attempts != numpages) {
		struct page *page;
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
			pr_debug("High order alloc test attempts: %lu (%lu)\n",
					attempts, alloced);
		}

		/* Print out a message every so often anyway */
		if (attempts > 0 && attempts % 10 == 0) {
			pr_debug("High order alloc test attempts: %lu (%lu)\n",
					attempts, alloced);
		}

		lastjiffies = jiffies;

		start_ktime = ktime_get_real();
		page = alloc_pages(gfp_flags | __GFP_NOWARN | __GFP_NORETRY, order);
		alloc_latencies[attempts] = ktime_sub (ktime_get_real(), start_ktime);

		if (page) {
			alloc_outcomes[attempts] = true;
			//pr_debug(testinfo, HIGHALLOC_BUDDYINFO, attempts, 1);
			success++;
			pages[alloced++] = page;

			/* Count what zone this is */
			zone = page_zone(page);
			if (zone->name != NULL && !strcmp(zone->name, "Movable")) page_easyrclm++;
			if (zone->name != NULL && !strcmp(zone->name, "HighMem")) page_highmem++;
			if (zone->name != NULL && !strcmp(zone->name, "Normal")) page_normal++;
			if (zone->name != NULL && !strcmp(zone->name, "DMA32")) page_dma32++;
			if (zone->name != NULL && !strcmp(zone->name, "DMA")) page_dma++;


			/* Give up if it takes more than 60 seconds to allocate */
			if (jiffies - lastjiffies > HZ * 600) {
				pr_debug("Took more than 600 seconds to allocate a block, giving up");
				aborted = attempts + 1;
				attempts = numpages;
				break;
			}

		} else {
			alloc_outcomes[attempts] = false;
			//printp_buddyinfo(testinfo, HIGHALLOC_BUDDYINFO, attempts, 0);
			fail++;

			/* Give up if it takes more than 30 seconds to fail */
			if (jiffies - lastjiffies > HZ * 1200) {
				pr_debug("Took more than 1200 seconds and still failed to allocate, giving up");
				aborted = attempts + 1;
				attempts = numpages;
				break;
			}
		}
		attempts++;
	}

	/* Disable preempt now to make sure everthing is actually printed */
	if (enabled_preempt) {
		preempt_disable();
		enabled_preempt = false;
	}

	for (printed = 0; printed < attempts; printed++)
		pr_debug("%lu %s %lu\n",
			printed,
			alloc_outcomes[printed] ? "success" : "failure",
			(unsigned long)ktime_to_ns(alloc_latencies[printed]));

	/* Re-enable OOM Killer state */
#ifdef OOM_DISABLED
	pr_debug("Re-enabling OOM Killer status\n");
	current->oomkilladj = oomkilladj;
#endif

	pr_debug("Test completed with %lu allocs, printing results\n", alloced);

	/* Print header */
	pr_debug("Order:                 %u\n", order);
	pr_debug("GFP flags:             0x%lx\n", (unsigned long)gfp_flags);
	pr_debug("Allocation type:       %s\n", (gfp_flags & __GFP_HIGHMEM) ? "HighMem" : "Normal");
	pr_debug("Attempted allocations: %lu\n", numpages);
	pr_debug("Success allocs:        %lu\n", success);
	pr_debug("Failed allocs:         %lu\n", fail);
	pr_debug("DMA32 zone allocs:       %lu\n", page_dma32);
	pr_debug("DMA zone allocs:       %lu\n", page_dma);
	pr_debug("Normal zone allocs:    %lu\n", page_normal);
	pr_debug("HighMem zone allocs:   %lu\n", page_highmem);
	pr_debug("EasyRclm zone allocs:  %lu\n", page_easyrclm);
	pr_debug("%% Success:            %lu\n", (success * 100) / (unsigned long)numpages);

	/*
	 * Free up the pages
	 */
	pr_debug("Test complete, freeing %lu pages\n", alloced);
	if (alloced > 0) {
		do {
			alloced--;
			if (pages[alloced] != NULL)
				__free_pages(pages[alloced], order);
		} while (alloced != 0);
	}

	if (aborted == 0)
		strcpy(finishString, "Test completed successfully\n");
	else
		sprintf(finishString, "Test aborted after %lu allocations due to delays\n", aborted);

	pr_debug("%s", finishString);

out_preempt:
	if (enabled_preempt)
		preempt_disable();

	if (alloc_latencies)
		vfree(alloc_latencies);
	if (alloc_outcomes)
		vfree(alloc_outcomes);
	if (pages)
		vfree(pages);

	return;
}

#ifdef CONFIG_DEBUG_FS
static int runtest_store(void *data, u64 val)
{
	runtest(order, count, gfp_flags, msdelay);

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

DEFINE_SIMPLE_ATTRIBUTE(runtest_fops, NULL, runtest_store, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(gfp_flags_fops, gfp_flags_show, gfp_flags_store, "0x%llx\n");

static int __init highalloc_test_debugfs_init(void)
{
	struct dentry *root;

	root = debugfs_create_dir("highalloc-test", NULL);
	if (root == NULL)
		return -ENXIO;

	debugfs_create_file("runtest", 0200, root, NULL, &runtest_fops);
	debugfs_create_u64("msdelay", 0644, root, &msdelay);
	debugfs_create_u64("count", 0644, root, &count);
	debugfs_create_u64("order", 0644, root, &order);
	debugfs_create_file("gfp_flags", 0644, root, NULL, &gfp_flags_fops);

	return 0;
}
#else
static int __init highalloc_test_debugfs_init(void) { return 0; }
#endif

static int highalloc_test_init(void)
{
	return highalloc_test_debugfs_init();
}

static void highalloc_test_exit(void)
{
}

module_init(highalloc_test_init);
module_exit(highalloc_test_exit);

MODULE_AUTHOR("Joonsoo Kim <iamjoonsoo.kim@lge.com>");
MODULE_LICENSE("GPL");
