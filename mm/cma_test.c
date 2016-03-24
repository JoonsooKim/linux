#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/cma.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#include "cma.h"

static int area_type;

static int run_type;
static int alloc_size;

static int __init early_cma_test_areas(char *buf)
{
	if (!buf)
		return -EINVAL;

	if (strcmp(buf, "hard") == 0)
		area_type = 1;
	else if (strcmp(buf, "normal") == 0)
		area_type = 2;
	else if (strcmp(buf, "easy") == 0)
		area_type = 3;
	else if (strcmp(buf, "compaction_benchmark") == 0)
		area_type = 4;

	return 0;
}
early_param("cma_test_areas", early_cma_test_areas);

static int __init param_cma_test_run(char *buf)
{
	if (!buf)
		return -EINVAL;

	if (strcmp(buf, "parallel") == 0) {
		area_type = 5;
		run_type = 1;
		alloc_size = 1;
	} else if (strcmp(buf, "merge") == 0) {
		area_type = 5;
		run_type = 1;
		alloc_size = 512;
	}

	return 0;
}
early_param("cma_test_run", param_cma_test_run);

void __init reserve_cma_test_areas(void)
{
	struct cma *cma;
	unsigned long limit = 0x0000000010000000;

	if (!area_type)
		return;

	switch (area_type) {
	case 1:
		cma_declare_contiguous(0, SZ_256M, 0, 0, 10, false, &cma);
		break;
	case 2:
	case 3:
		cma_declare_contiguous(0, SZ_128M, 0, 0, 1, false, &cma);
		break;
	case 4:
		cma_declare_contiguous(0, SZ_64M, limit, 0, 0, false, &cma);
		break;
	case 5:
		cma_declare_contiguous(0, SZ_256M, 0, 0, 0, false, &cma);
		break;
	default:
		break;
	}
}

static int alloc_cma(void *data)
{
	int i;
	struct page *page;

	for (i = 0; i < 1000; i++) {

		page = cma_alloc(&cma_areas[0], alloc_size, 0);

		mdelay(1);

		if (page)
			cma_release(&cma_areas[0], page, alloc_size);
	}

	return 0;
}

static int cma_test_run(void)
{
	int i;
	struct task_struct **task;

	if (!run_type)
		return 0;

	printk("%s: size: %d\n", __func__, alloc_size);
	task = kzalloc(sizeof(void *) * 100, GFP_KERNEL);
	for (i = 0; i < 100; i++) {
		task[i] = kthread_create(alloc_cma, NULL, "alloc_cma_%d", i);
		if (!task[i]) {
			printk("JOONSOO: FAIL\n");
			return 1;
		}
	}

	for (i = 0; i < 100; i++)
		wake_up_process(task[i]);

	msleep(1000);
	return 0;
}
late_initcall(cma_test_run);
