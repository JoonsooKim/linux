#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/cma.h>

static int area_type;

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
	default:
		break;
	}
}
