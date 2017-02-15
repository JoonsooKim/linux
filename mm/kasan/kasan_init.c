/*
 * This file contains some kasan initialization code.
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/bootmem.h>
#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/pfn.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/pgalloc.h>

#include "kasan.h"

unsigned long kasan_pshadow_offset __read_mostly;
unsigned long kasan_black_page_pfn __read_mostly;

/*
 * This page serves two purposes:
 *   - It used as early shadow memory. The entire shadow region populated
 *     with this page, before we will be able to setup normal shadow memory.
 *   - Latter it reused it as zero shadow to cover large ranges of memory
 *     that allowed to access, but not handled by kasan (vmalloc/vmemmap ...).
 */
unsigned char kasan_zero_page[PAGE_SIZE] __page_aligned_bss;

/*
 * The shadow memory range that this page is mapped will be considered
 * to be checked later by another shadow memory.
 */
unsigned char kasan_black_page[PAGE_SIZE] __page_aligned_bss;

#if CONFIG_PGTABLE_LEVELS > 3
pud_t kasan_zero_pud[PTRS_PER_PUD] __page_aligned_bss;
pud_t kasan_black_pud[PTRS_PER_PUD] __page_aligned_bss;
#endif
#if CONFIG_PGTABLE_LEVELS > 2
pmd_t kasan_zero_pmd[PTRS_PER_PMD] __page_aligned_bss;
pmd_t kasan_black_pmd[PTRS_PER_PMD] __page_aligned_bss;
#endif
pte_t kasan_zero_pte[PTRS_PER_PTE] __page_aligned_bss;
pte_t kasan_black_pte[PTRS_PER_PTE] __page_aligned_bss;

static __init void *early_alloc(size_t size, int node)
{
	return memblock_virt_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
					BOOTMEM_ALLOC_ACCESSIBLE, node);
}

static void __init kasan_pte_populate(pmd_t *pmd, unsigned long addr,
				unsigned long end, bool zero)
{
	pte_t *ptep = pte_offset_kernel(pmd, addr);
	pte_t pte;
	unsigned char *page = zero ? kasan_zero_page : kasan_black_page;

	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
	pte = pte_wrprotect(pte);

	while (addr + PAGE_SIZE <= end) {
		set_pte_at(&init_mm, addr, ptep, pte);
		addr += PAGE_SIZE;
		ptep = pte_offset_kernel(pmd, addr);
	}

	if (addr == end)
		return;

	/* Population for unaligned end address */
	page = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
	if (!zero)
		__memcpy(page, kasan_black_page, end - addr);

	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
	set_pte_at(&init_mm, addr, ptep, pte);
}

static void __init kasan_pmd_populate(pud_t *pud, unsigned long addr,
				unsigned long end, bool zero, bool private)
{
	pmd_t *pmd = pmd_offset(pud, addr);
	unsigned long next;

	do {
		next = pmd_addr_end(addr, end);

		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE &&
			!private) {
			pmd_populate_kernel(&init_mm, pmd,
				zero ? kasan_zero_pte : kasan_black_pte);
			continue;
		}

		if (pmd_none(*pmd)) {
			pmd_populate_kernel(&init_mm, pmd,
					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
		}

		kasan_pte_populate(pmd, addr, next, zero);
	} while (pmd++, addr = next, addr != end);
}

static void __init kasan_pud_populate(pgd_t *pgd, unsigned long addr,
				unsigned long end, bool zero, bool private)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		if (IS_ALIGNED(addr, PUD_SIZE) && end - addr >= PUD_SIZE &&
			!private) {
			pmd_t *pmd;

			pud_populate(&init_mm, pud,
				zero ? kasan_zero_pmd : kasan_black_pmd);
			pmd = pmd_offset(pud, addr);
			pmd_populate_kernel(&init_mm, pmd,
				zero ? kasan_zero_pte : kasan_black_pte);
			continue;
		}

		if (pud_none(*pud)) {
			pud_populate(&init_mm, pud,
				early_alloc(PAGE_SIZE, NUMA_NO_NODE));
		}
		kasan_pmd_populate(pud, addr, next, zero, private);
	} while (pud++, addr = next, addr != end);
}

/**
 * kasan_populate_shadow - populate shadow memory region with
 *                               kasan_(zero|black)_page
 * @shadow_start - start of the memory range to populate
 * @shadow_end   - end of the memory range to populate
 * @zero	 - type of populated shadow, zero and black
 * @private	 - force to populate private shadow except the last page
 */
void __init kasan_populate_shadow(const void *shadow_start,
				const void *shadow_end,
				bool zero, bool private)
{
	unsigned long addr = (unsigned long)shadow_start;
	unsigned long end = (unsigned long)shadow_end;
	pgd_t *pgd = pgd_offset_k(addr);
	unsigned long next;

	do {
		next = pgd_addr_end(addr, end);

		if (IS_ALIGNED(addr, PGDIR_SIZE) && end - addr >= PGDIR_SIZE &&
			!private) {
			pud_t *pud;
			pmd_t *pmd;

			/*
			 * kasan_zero_pud should be populated with pmds
			 * at this moment.
			 * [pud,pmd]_populate*() below needed only for
			 * 3,2 - level page tables where we don't have
			 * puds,pmds, so pgd_populate(), pud_populate()
			 * is noops.
			 */
			pgd_populate(&init_mm, pgd,
				zero ? kasan_zero_pud : kasan_black_pud);
			pud = pud_offset(pgd, addr);
			pud_populate(&init_mm, pud,
				zero ? kasan_zero_pmd : kasan_black_pmd);
			pmd = pmd_offset(pud, addr);
			pmd_populate_kernel(&init_mm, pmd,
				zero ? kasan_zero_pte : kasan_black_pte);
			continue;
		}

		if (pgd_none(*pgd)) {
			pgd_populate(&init_mm, pgd,
				early_alloc(PAGE_SIZE, NUMA_NO_NODE));
		}
		kasan_pud_populate(pgd, addr, next, zero, private);
	} while (pgd++, addr = next, addr != end);
}

void __init kasan_early_init_pshadow(void)
{
	static struct vm_struct pshadow;
	unsigned long kernel_offset;
	int i;

	/*
	 * Temprorary map per-page shadow to per-byte shadow in order to
	 * pass the KASAN checks in vm_area_register_early()
	 */
	kernel_offset = (unsigned long)kasan_shadow_to_mem(
					(void *)KASAN_SHADOW_START);
	kasan_pshadow_offset = KASAN_SHADOW_START -
				(kernel_offset >> PAGE_SHIFT);

	pshadow.size = KASAN_PSHADOW_SIZE;
	pshadow.flags = VM_ALLOC | VM_NO_GUARD;
	vm_area_register_early(&pshadow,
		(PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT));

	kasan_pshadow_offset = (unsigned long)pshadow.addr -
					(kernel_offset >> PAGE_SHIFT);

	BUILD_BUG_ON(KASAN_FREE_PAGE != KASAN_PER_PAGE_BYPASS);
	kasan_black_page_pfn = PFN_DOWN(__pa(kasan_black_page));
	for (i = 0; i < PAGE_SIZE; i++)
		kasan_black_page[i] = KASAN_FREE_PAGE;
}
