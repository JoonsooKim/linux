#ifndef _ASM_KASAN_H_
#define _ASM_KASAN_H_

#include <linux/const.h>
#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)

#ifdef CONFIG_KASAN

#include <asm/memory.h>

/*
 * Compiler uses shadow offset assuming that addresses start
 * from 0. Kernel addresses don't start from 0, so shadow
 * for kernel really starts from 'compiler's shadow offset' +
 * ('kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT)
 */
#define KASAN_SHADOW_START     (KASAN_SHADOW_OFFSET)

#define KASAN_SHADOW_END       (KASAN_SHADOW_START + (1ULL << 29))

void __init kasan_init(void);

#else

static inline void kasan_init(void) { }

#endif

#endif /* _ASM_KASAN_H_ */
