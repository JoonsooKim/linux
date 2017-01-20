#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/workqueue.h>

/*
 * How to use this sample for vchecker sample-run
 *
 * 1. Insert this module
 * 2. Do following command on debugfs directory
 *    # cd /sys/kernel/debug/vchecker
 *    # echo 0 0xffff 7 > vchecker_test/value # offset 0, mask 0xffff, value 7
 *    # echo 1 > vchecker_test/enable
 *    # echo workfn_kmalloc_obj > kmalloc-8/alloc_filter
 *    # echo "0 8" > kmalloc-8/callstack
 *    # echo on > kmalloc-8/callstack
 *    # echo 1 > kmalloc-8/enable
 * 3. Check the error report due to invalid written value
 */

struct object {
	volatile unsigned long v[1];
};

static struct kmem_cache *s;
static void *old_obj;
static struct delayed_work dwork_old_obj;
static struct delayed_work dwork_new_obj;
static struct delayed_work dwork_kmalloc_obj;

static void workfn_old_obj(struct work_struct *work)
{
	struct object *obj = old_obj;
	struct delayed_work *dwork = (struct delayed_work *)work;

	obj->v[0] = 7;

	mod_delayed_work(system_wq, dwork, HZ * 5);
}

static void workfn_new_obj(struct work_struct *work)
{
	struct object *obj;
	struct delayed_work *dwork = (struct delayed_work *)work;

	obj = kmem_cache_alloc(s, GFP_KERNEL);

	obj->v[0] = 7;
	/*
	 * Need one more access to detect wrong value since there is
	 * no proper infrastructure yet and the feature is just emulated.
	 */
	obj->v[0] = 0;

	kmem_cache_free(s, obj);
	mod_delayed_work(system_wq, dwork, HZ * 5);
}

static void workfn_kmalloc_obj(struct work_struct *work)
{
	struct object *obj;
	struct delayed_work *dwork = (struct delayed_work *)work;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);

	obj->v[0] = 7;
	/*
	 * Need one more access to detect wrong value since there is
	 * no proper infrastructure yet and the feature is just emulated.
	 */
	obj->v[0] = 0;

	kfree(obj);
	mod_delayed_work(system_wq, dwork, HZ * 5);
}

static int __init vchecker_test_init(void)
{
	s = kmem_cache_create("vchecker_test",
			sizeof(struct object), 0, SLAB_NOLEAKTRACE, NULL);
	if (!s)
		return 1;

	old_obj = kmem_cache_alloc(s, GFP_KERNEL);
	if (!old_obj) {
		kmem_cache_destroy(s);
		return 1;
	}

	INIT_DELAYED_WORK(&dwork_old_obj, workfn_old_obj);
	INIT_DELAYED_WORK(&dwork_new_obj, workfn_new_obj);
	INIT_DELAYED_WORK(&dwork_kmalloc_obj, workfn_kmalloc_obj);

	mod_delayed_work(system_wq, &dwork_old_obj, HZ * 5);
	mod_delayed_work(system_wq, &dwork_new_obj, HZ * 5);
	mod_delayed_work(system_wq, &dwork_kmalloc_obj, HZ * 5);

	return 0;
}

static void __exit vchecker_test_fini(void)
{
	cancel_delayed_work_sync(&dwork_old_obj);
	cancel_delayed_work_sync(&dwork_new_obj);
	cancel_delayed_work_sync(&dwork_kmalloc_obj);

	kmem_cache_free(s, old_obj);
	kmem_cache_destroy(s);
}


module_init(vchecker_test_init);
module_exit(vchecker_test_fini)

MODULE_LICENSE("GPL");

