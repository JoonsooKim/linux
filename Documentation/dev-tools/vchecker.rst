The Valid Access Checker (VCHECKER)
===================================

Overview
--------
Vchecker is a dynamic memory error detector. It provides a new debug feature
that can find out an un-intended access to valid area. Valid area here means
the memory which is allocated and allowed to be accessed by memory owner and
un-intended access means the read/write that is initiated by non-owner.
Usual problem of this class is memory overwritten.

Most of debug feature focused on finding out un-intended access to
in-valid area, for example, out-of-bound access and use-after-free, and,
there are many good tools for it. But, as far as I know, there is no good tool
to find out un-intended access to valid area. This kind of problem is really
hard to solve so this tool would be very useful.

This tool doesn't automatically catch a problem. Manual configuration to
specify the target object is required. See the usage part on the below.

Usage
-----

To enable vchecker configure kernel with

::

	CONFIG_VCHECKER = y

and choose the target slab object type and the type of the checkers by debugfs
interface at the runtime. Following is the hierarchy of the interface.

::

	- debugfs root for vchecker
		- directory per slab cache
			- alloc_filter
			- callstack_depth
			- enable
			- value
			- callstack


alloc_filter can be used to apply the checker to specific allocation caller
for this slab cache. For example, there are multiple users for kmalloc-N
slab cache and it's better to filter out un-related allocation caller
when debugging. Note that, if alloc_filter is specified, vchecker doesn't
regard existing allocated objects as debugging target since it's not easy
to know the allocation caller for existing allocated objects.

callstack_depth can be used to limit the depth of callstack. It would be
helpful to reduce overhead.

enable can be used to begin/end the checker for this slab cache.

There are two checkers now, value checker and callstack checker.

Value checker checks the value stored in the target object.
See following example.

::

	static void workfn(struct work_struct *work)
	{
		struct object *obj;
		struct delayed_work *dwork = (struct delayed_work *)work;

		obj = kmem_cache_alloc(s, GFP_KERNEL);

		obj->v[0] = 7;
		obj->v[0] = 0;

		kmem_cache_free(s, obj);
		mod_delayed_work(system_wq, dwork, HZ);
	}

Assume that v[0] should not be the value, 7, however, there is a code
to set v[0] to the value, 7. To detect this error, register the value checker
for this object and specify that invalid value is '7'. After registration,
if someone stores '7' to this object, the error will be reported. Registration
can be done by three parameter as following.

::

	# cd /sys/kernel/debug/vchecker
	# echo 0 0xffff 7 > [slab cache]/value
		// offset 0 (dec)
		// mask 0xffff (hex)
		// value 7 (dec)
	# echo 1 > [slab cache]/enable

Before describing the each parameters, one thing should be noted. One value
checker works for 8 bytes at maximum. If more bytes should be checked,
please register multiple value checkers.

First parameter is a target offset from the object base. It should be aligned
by 8 bytes due to implementation constraint. Second parameter is a mask that
is used to specify the range in the specified 8 bytes. Occasionally, we want to
check just 1 byte or 1 bit and this mask makes it possible to check such
a small range. Third parameter is the value that is assumed as invalid.

Second checker is the callstack checker. It checks the read/write callstack
of the target object. Overwritten problem usually happens by non-owner and
it would have odd callstack. By checking the oddity of the callstack, vchecker
can report the possible error candidate. Currently, the oddity of the callstack
is naively determined by checking whether it is a new callstack or not. It can
be extended to use whitelist but not yet implemented.

::

	# echo 0 8 > [slab cache]/callstack
		// offset 0 (dec)
		// size 8 (dec)
	# echo 1 > [slab cache]/enable

First parameter is a target offset as usual and the second one is the size to
determine the range. Unlike the value checker, callstack checker can check
more than 8 bytes by just one checker.

::

	# echo off > [slab cache]/callstack
		// ... (do some work to collect enough valid callstacks) ...
	# echo on > [slab cache]/callstack

You can collect potential valid callstack during 'off state'. If you think
that enough callstacks are collected, turn on the checker. It will report
a new callstack and it may be a bug candidate.

Error reports
-------------

Report format looks very similar with the report of KASAN

::

	[   49.400673] ==================================================================
	[   49.402297] BUG: VCHECKER: invalid access in workfn_old_obj+0x14/0x50 [vchecker_test] at addr ffff88002e9dc000
	[   49.403899] Write of size 8 by task kworker/0:2/465
	[   49.404538] value checker for offset 0 ~ 8 at ffff88002e9dc000
	[   49.405374] (mask 0xffff value 7) invalid value 7

	[   49.406016] Invalid writer:
	[   49.406302]  workfn_old_obj+0x14/0x50 [vchecker_test]
	[   49.406973]  process_one_work+0x3b5/0x9f0
	[   49.407463]  worker_thread+0x87/0x750
	[   49.407895]  kthread+0x1b2/0x200
	[   49.408252]  ret_from_fork+0x24/0x30

	[   49.408723] Allocated by task 1326:
	[   49.409126]  kasan_kmalloc+0xb9/0xe0
	[   49.409571]  kmem_cache_alloc+0xd1/0x250
	[   49.410046]  0xffffffffa00c8157
	[   49.410389]  do_one_initcall+0x82/0x1cf
	[   49.410851]  do_init_module+0xe7/0x333
	[   49.411296]  load_module+0x406b/0x4b40
	[   49.411745]  SYSC_finit_module+0x14d/0x180
	[   49.412247]  do_syscall_64+0xf0/0x340
	[   49.412674]  return_from_SYSCALL_64+0x0/0x75

	[   49.413276] Freed by task 0:
	[   49.413566] (stack is not available)

	[   49.414034] The buggy address belongs to the object at ffff88002e9dc000
	                which belongs to the cache vchecker_test of size 8
	[   49.415708] The buggy address is located 0 bytes inside of
	                8-byte region [ffff88002e9dc000, ffff88002e9dc008)
	[   49.417148] ==================================================================

It shows that vchecker find the invalid value writing
at workfn_old_obj+0x14/0x50. Object information is also reported.

Implementation details
----------------------
This part requires some understanding of how KASAN works since vchecker is
highly depends on shadow memory of KASAN. Vchecker uses the shadow to
distinguish interesting memory address for validation. If it finds the special
value on the shadow of the accessing address, it means that this address is
the target for validation check. Then, it tries to do additional checks to this
address. With this way, vchecker can filter out un-interesting memory access
very efficiently.

A new type of checks can be added by implementing following callback structure.
check() callback is the main function that checks whether the access is valid
or not. Please reference existing checkers for more information.

::

	struct vchecker_type {
		char *name;
		const struct file_operations *fops;
		int (*init)(struct kmem_cache *s, struct vchecker_cb *cb,
				char *buf, size_t cnt);
		void (*fini)(struct vchecker_cb *cb);
		void (*show)(struct kmem_cache *s, struct seq_file *f,
				struct vchecker_cb *cb, void *object, bool verbose);
		bool (*check)(struct kmem_cache *s, struct vchecker_cb *cb,
				void *object, bool write, unsigned long ret_ip,
				unsigned long begin, unsigned long end);
	};
