#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/workqueue.h>

struct object {
	volatile unsigned long v[3];
};

static struct kmem_cache *s;
static struct delayed_work dwork_new_obj;
static struct delayed_work dwork_old_obj;
static void *old_obj;

static void workfn_new_obj(struct work_struct *work)
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

static void workfn_old_obj(struct work_struct *work)
{
	struct object *obj = old_obj;
	struct delayed_work *dwork = (struct delayed_work *)work;

	obj->v[0] = 7;
	obj->v[1] = 5;
	obj->v[2] = 9;
	obj->v[1] = 4;
	obj->v[2] = obj->v[1];

	mod_delayed_work(system_wq, dwork, HZ);
}

static int __init vchecker_test_init(void)
{
	INIT_DELAYED_WORK(&dwork_new_obj, workfn_new_obj);
	INIT_DELAYED_WORK(&dwork_old_obj, workfn_old_obj);
	s = kmem_cache_create("vchecker_test",
			sizeof(struct object), 0, SLAB_NOLEAKTRACE, NULL);
	mod_delayed_work(system_wq, &dwork_new_obj, HZ);

	old_obj = kmem_cache_alloc(s, GFP_KERNEL);
	mod_delayed_work(system_wq, &dwork_old_obj, HZ);

	return 0;
}

static void __exit vchecker_test_fini(void)
{
	cancel_delayed_work_sync(&dwork_new_obj);
	cancel_delayed_work_sync(&dwork_old_obj);
	kmem_cache_free(s, old_obj);
	kmem_cache_destroy(s);
}


module_init(vchecker_test_init);
module_exit(vchecker_test_fini)

MODULE_LICENSE("GPL");

