#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/workqueue.h>

struct object {
	volatile unsigned long v[3];
};

static struct kmem_cache *s;
static struct delayed_work dwork;

static void workfn(struct work_struct *work)
{
	struct object *obj;
	struct delayed_work *dwork = (struct delayed_work *)work;

	obj = kmem_cache_alloc(s, GFP_KERNEL);

	obj->v[0] = 7;
	obj->v[1] = 5;
	obj->v[2] = 9;
	obj->v[1] = 4;
	obj->v[2] = obj->v[1];

	kmem_cache_free(s, obj);
	mod_delayed_work(system_wq, dwork, HZ);
}

static int __init vchecker_test_init(void)
{
	INIT_DELAYED_WORK(&dwork, workfn);
	s = kmem_cache_create("vchecker_test",
			sizeof(struct object), 0, SLAB_NOLEAKTRACE, NULL);
	mod_delayed_work(system_wq, &dwork, HZ);

	return 0;
}

static void __exit vchecker_test_fini(void)
{
	cancel_delayed_work_sync(&dwork);
	kmem_cache_destroy(s);
}


module_init(vchecker_test_init);
module_exit(vchecker_test_fini)

MODULE_LICENSE("GPL");

