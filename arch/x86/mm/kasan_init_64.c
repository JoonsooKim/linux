#define pr_fmt(fmt) "kasan: " fmt
#include <linux/bootmem.h>
#include <linux/kasan.h>
#include <linux/kdebug.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/memblock.h>

#include <asm/tlbflush.h>
#include <asm/sections.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern struct range pfn_mapped[E820_X_MAX];

static __init void *early_alloc(size_t size, int node)
{
	return memblock_virt_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
					BOOTMEM_ALLOC_ACCESSIBLE, node);
}

static int __init map_range(struct range *range, bool pshadow)
{
	unsigned long start;
	unsigned long end;

	start = (unsigned long)pfn_to_kaddr(range->start);
	end = (unsigned long)pfn_to_kaddr(range->end);

	/*
	 * end + 1 here is intentional. We check several shadow bytes in advance
	 * to slightly speed up fastpath. In some rare cases we could cross
	 * boundary of mapped shadow, so we just map some more here.
	 */
	if (pshadow) {
		start = (unsigned long)kasan_mem_to_pshadow((void *)start);
		end = (unsigned long)kasan_mem_to_pshadow((void *)end);

		return vmemmap_populate(start, end + 1, NUMA_NO_NODE);
	} else {
		start = (unsigned long)kasan_mem_to_shadow((void *)start);
		end = (unsigned long)kasan_mem_to_shadow((void *)end);

		kasan_populate_shadow((void *)start, (void *)end + 1,
						false, true);
		return 0;
	}
}

static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}

static void __init kasan_map_early_shadow(pgd_t *pgd,
			unsigned long start, unsigned long end)
{
	int i;

	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(kasan_zero_pud)
				| _KERNPG_TABLE);
		start += PGDIR_SIZE;
	}
}

#ifdef CONFIG_KASAN_INLINE
static int kasan_die_handler(struct notifier_block *self,
			     unsigned long val,
			     void *data)
{
	if (val == DIE_GPF) {
		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
	}
	return NOTIFY_OK;
}

static struct notifier_block kasan_die_notifier = {
	.notifier_call = kasan_die_handler,
};
#endif

void __init kasan_early_init(void)
{
	int i;
	pteval_t pte_val = __pa_nodebug(kasan_zero_page) | __PAGE_KERNEL;
	pmdval_t pmd_val = __pa_nodebug(kasan_zero_pte) | _KERNPG_TABLE;
	pudval_t pud_val = __pa_nodebug(kasan_zero_pmd) | _KERNPG_TABLE;

	for (i = 0; i < PTRS_PER_PTE; i++)
		kasan_zero_pte[i] = __pte(pte_val);

	for (i = 0; i < PTRS_PER_PMD; i++)
		kasan_zero_pmd[i] = __pmd(pmd_val);

	for (i = 0; i < PTRS_PER_PUD; i++)
		kasan_zero_pud[i] = __pud(pud_val);

	kasan_map_early_shadow(early_level4_pgt,
		KASAN_SHADOW_START, KASAN_SHADOW_END);
	kasan_map_early_shadow(init_level4_pgt,
		KASAN_SHADOW_START, KASAN_SHADOW_END);

	kasan_early_init_pshadow();

	kasan_map_early_shadow(early_level4_pgt,
		KASAN_PSHADOW_START, KASAN_PSHADOW_END);
	kasan_map_early_shadow(init_level4_pgt,
		KASAN_PSHADOW_START, KASAN_PSHADOW_END);

	/* Prepare black shadow memory */
	pte_val = __pa_nodebug(kasan_black_page) | __PAGE_KERNEL_RO;
	pmd_val = __pa_nodebug(kasan_black_pte) | _KERNPG_TABLE;
	pud_val = __pa_nodebug(kasan_black_pmd) | _KERNPG_TABLE;

	for (i = 0; i < PTRS_PER_PTE; i++)
		kasan_black_pte[i] = __pte(pte_val);

	for (i = 0; i < PTRS_PER_PMD; i++)
		kasan_black_pmd[i] = __pmd(pmd_val);

	for (i = 0; i < PTRS_PER_PUD; i++)
		kasan_black_pud[i] = __pud(pud_val);
}

void __init kasan_init(void)
{
	int i;

#ifdef CONFIG_KASAN_INLINE
	register_die_notifier(&kasan_die_notifier);
#endif

	memcpy(early_level4_pgt, init_level4_pgt, sizeof(early_level4_pgt));
	load_cr3(early_level4_pgt);
	__flush_tlb_all();

	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);

	kasan_populate_shadow((void *)KASAN_SHADOW_START,
			kasan_mem_to_shadow((void *)PAGE_OFFSET),
			true, false);

	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		if (map_range(&pfn_mapped[i], false))
			panic("kasan: unable to allocate shadow!");
	}
	kasan_populate_shadow(
		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
		kasan_mem_to_shadow((void *)__START_KERNEL_map),
		true, false);

	vmemmap_populate((unsigned long)kasan_mem_to_shadow(_stext),
			(unsigned long)kasan_mem_to_shadow(_end),
			NUMA_NO_NODE);

	kasan_populate_shadow(kasan_mem_to_shadow((void *)MODULES_END),
			(void *)KASAN_SHADOW_END,
			true, false);

	/* For per-page shadow */
	clear_pgds(KASAN_PSHADOW_START, KASAN_PSHADOW_END);

	kasan_populate_shadow((void *)KASAN_PSHADOW_START,
			kasan_mem_to_pshadow((void *)PAGE_OFFSET),
			true, false);

	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		if (map_range(&pfn_mapped[i], true))
			panic("kasan: unable to allocate shadow!");
	}
	kasan_populate_shadow(
		kasan_mem_to_pshadow((void *)PAGE_OFFSET + MAXMEM),
		kasan_mem_to_pshadow((void *)__START_KERNEL_map),
		true, false);

	kasan_populate_shadow(
		kasan_mem_to_pshadow(_stext),
		kasan_mem_to_pshadow(_end),
		false, false);

	kasan_populate_shadow(
		kasan_mem_to_pshadow((void *)MODULES_VADDR),
		kasan_mem_to_pshadow((void *)MODULES_END),
		false, false);

	kasan_populate_shadow(kasan_mem_to_pshadow((void *)MODULES_END),
			(void *)KASAN_PSHADOW_END,
			true, false);

	load_cr3(init_level4_pgt);
	__flush_tlb_all();

	/*
	 * kasan_zero_page has been used as early shadow memory, thus it may
	 * contain some garbage. Now we can clear and write protect it, since
	 * after the TLB flush no one should write to it.
	 */
	memset(kasan_zero_page, 0, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte_t pte = __pte(__pa(kasan_zero_page) | __PAGE_KERNEL_RO);
		set_pte(&kasan_zero_pte[i], pte);
	}
	/* Flush TLBs again to be sure that write protection applied. */
	__flush_tlb_all();

	init_task.kasan_depth = 0;
	pr_info("KernelAddressSanitizer initialized\n");
}

static void __init kasan_map_shadow_late(unsigned long start,
					unsigned long end)
{
	unsigned long addr;
	unsigned char *page;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	pte_t pte;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
		pmd = pmd_offset(pud, addr);
		ptep = pte_offset_kernel(pmd, addr);

		page = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
		pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
		set_pte_at(&init_mm, addr, ptep, pte);
	}
}

static void __init __kasan_init_late(unsigned long start, unsigned long end)
{
	unsigned long shadow_start, shadow_end;

	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)start);
	shadow_start = round_down(shadow_start, PAGE_SIZE);
	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)end);
	shadow_end = ALIGN(shadow_end, PAGE_SIZE);

	kasan_map_shadow_late(shadow_start, shadow_end);
	kasan_poison_pshadow((void *)start, ALIGN(end, PAGE_SIZE) - start);
}

void __init kasan_init_late(void)
{
	int cpu;
	unsigned long start, end;

	for_each_possible_cpu(cpu) {
		end   = (unsigned long)per_cpu(irq_stack_ptr, cpu);
		start = end - IRQ_STACK_SIZE;

		__kasan_init_late(start, end);

		start = (unsigned long)per_cpu(exception_stacks, cpu);
		end = start + sizeof(exception_stacks);

		__kasan_init_late(start, end);
	}
}

/*
 * We cannot flush the TLBs in other cpus due to deadlock
 * so just flush the TLB in current cpu. Accessing stale TLB
 * entry would happen only if invalid access happens since it is
 * freed area. However, it is possible so we should consider
 * the solution.
 *
 * 1. write protection fault: It will be handled by spurious
 * fault handler. It will invalidate stale TLB entry.
 * 2. false-positive in KASAN shadow check: It will be
 * handled by re-check with flushing local TLB.
 */
void arch_kasan_map_shadow(unsigned long s, unsigned long e)
{
	__flush_tlb_all();
}

bool arch_kasan_recheck_prepare(unsigned long addr, size_t size)
{
	__flush_tlb_all();

	return true;
}
