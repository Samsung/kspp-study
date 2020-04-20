@sidebar(Heap Overflows)
# Mitigating Heap Overflows

## Protecting the integrity of heap metadata
@kconfig(CONFIG_DEBUG_LIST)
@kconfig(CONFIG_SLAB_FREELIST_HARDENED)
@kconfig(CONFIG_SLAB_FREELIST_RANDOM)


Manipulating a list entry, if crafted, introduces a traditionally,
well-known attack vector, as known as _usafe unlink_. Simply put, an
attacker can launch an semi-arbitrary memory write by overwriting the
list entry (e.g., via heap overflow), illustrated like below:

~~~~
# TODO. draw a real figure

  prev           cur            next
 +------+       +------+       +------+
 |      |------>| PPPP-|------>|      |
 |      |<------|-VVVV |<------|      |
 +------+       +------+       +------+

 *(PPPP+8) = VVVV
 *VVVV = PPPP (restricted)

 so to do *dst = val, an attacker can overwrite cur's list by [dst-8, val].
~~~~

Before deleting a list entry, it firsts performs an integrity check,
`__list_del_entry_valid()`, and after the deletion, it poisons
the list entries to assist better debugging---it tends to prevent
data pointer leaks when there is a dangling pointer to the freed object.

~~~~{.c}
// @include/linux/list.h
void list_del(struct list_head *entry)
{
  __list_del_entry(entry);

  entry->next = LIST_POISON1; // 0xdead000000000100 
  entry->prev = LIST_POISON2; // 0xdead000000000200 
}

void __list_del_entry(struct list_head *entry)
{
  if (!__list_del_entry_valid(entry))
    return;
  __list_del(entry->prev, entry->next);
}

void __list_del(struct list_head * prev, struct list_head * next)
{
  next->prev = prev;
  prev->next = next;
}
~~~~

Two conditions are checked:
1) whether attempting to perform a deletion on a freed list entry
(e.g., double delete);
2) the indicated previous entry points to itself, vise versa for the
indicated next entry.
For 1), `POISON1/2` inserted during the deletion process help to
recognize the invariant. These checks are similarly performed for the
addition.

~~~~{.c}
bool __list_del_entry_valid(struct list_head *entry)
{
  struct list_head *prev, *next;

  prev = entry->prev;
  next = entry->next;

  // NB. first check if we are attempting to delete
  // previous deleted entry
  if (CHECK_DATA_CORRUPTION(next == LIST_POISON1,
       "list_del corruption, %px->next is LIST_POISON1 (%px)\n",
       entry, LIST_POISON1) ||
      CHECK_DATA_CORRUPTION(prev == LIST_POISON2,
       "list_del corruption, %px->prev is LIST_POISON2 (%px)\n",
       entry, LIST_POISON2) ||

  // NB. check the integrity of the link chains; prev's next and
  // next's prev correctly point to me

      CHECK_DATA_CORRUPTION(prev->next != entry,
       "list_del corruption. prev->next should be %px, but was %px\n",
       entry, prev->next) ||
      CHECK_DATA_CORRUPTION(next->prev != entry,
       "list_del corruption. next->prev should be %px, but was %px\n",
       entry, next->prev))
    return false;
  return true;
}
~~~~

__SLAB_FREELIST_RANDOM.__
The determinism (i.e., the deterministic order in allocated chunks)
helps (a bit) an attacker
in controlling the overflowing target.
The simple way to disturb the determinism is to randomize
its allocation order;
it can be done by randomizing the free chunks
when the kmem_cache structure is initialized.
The Fisher-Yates algorithm implemented
in `freelist_randomize()`
can guarantee that each slot has
the equal likelihood for being randomized.

~~~~{.c}
// @mm/slab_common.c
// init_freelist_randomization()
//   -> init_cache_random_seq()
//     -> cache_random_seq_create()
void freelist_randomize(struct rnd_state *state, unsigned int *list,
                        unsigned int count)
{
  unsigned int rand;
  unsigned int i;

  for (i = 0; i < count; i++)
    list[i] = i;

  /* Fisher-Yates shuffle */
  for (i = count - 1; i > 0; i--) {
    rand = prandom_u32_state(state);
    rand %= (i + 1);
    swap(list[i], list[rand]);
  }
}
~~~~

__CONFIG_SLAB_FREELIST_HARDENED.__
When a heap object is overflowed,
there exist two classes of overflowing targets 
(i.e., the nearby object located right after), namely,
1) a free object, and 2) an allocated object,
with the same type.
In terms of exploits,
one approach is to abuse some specific semantics
of the target objects (e.g., crafting a function pointer in the `struct`),
but another approach is to
develop the overflow into
more preferable primitives
(e.g., arbitrary write)
for exploitation.
In case of the free object (the second case),
there exists a _generic_ approach,
meaning that the metatdata of heap structures
is abused for further exploitation.
For example, the link structure, called `freelist`,
that chains all free objects in the cache,
can be overwritten in a way
that can be crafted for creating dangling pointers
(e.g., returning an arbitrary object pointer
when `kmalloc()` is invoked).


~~~~
// TODO. redraw a real figure

 ---> freelist that link all free chunks
 
        head ---+
                V
 +------+       +------+       +------+
 |      |<------|-     |       |      |
 +------+  ptr  +------+       +------+
 |              (ptr_addr)     ^
 +-----------------------------+ 
~~~~

`SLAB_FREELIST_HARDENED` is proposed to
prevent this direct modification
of the `freelist` structure.
The basic approach is to _mangle_
(xor)
the pointer with a random canary value
(`s->random`)
created at the initialization of the cache.
One interesting decision is to add `ptr_addr`
to the mangled pointer.
Its implication is subtle, but worth mentioning here.
If `s->random` is leaked via another channel,
an attacker can place
an arbitrary value (i.e., the value xor-ed with the canary),
allowing the aforementioned exploitation techniques possible again.
The proposed solution is
to mangle the value once more
with another secrete value,
the randomized address of the chunk itself (ptr_addr).
To bypass this protection,
the attacker should be able to locate
the overflowing chunk precisely.
However, one potential concern
would be that
an attacker can reuse its value in a simple arithmetic:
e.g., adding the size of the heap object, say 0x100,
to the leaked data
would likely lead to a controllable situation,
like two freed objects or one allocated object
now in the `freelist`.

~~~~{.c}
/*
 * Returns freelist pointer (ptr). With hardening, this is obfuscated
 * with an XOR of the address where the pointer is held and a per-cache
 * random number.
 */
void *freelist_ptr(const struct kmem_cache *s, void *ptr,
                   unsigned long ptr_addr) {
  return (void *)((unsigned long)ptr ^ s->random ^ ptr_addr));
}
~~~~


### Performance implication

TODO. set a target benchmarks in /bench


### References
1. [Slab allocators in the Linux Kernel:SLAB, SLOB, SLUB](https://events.static.linuxfound.org/sites/events/files/slides/slaballocators.pdf)
2. [How does the SLUB allocator work](https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf)
3. [The Slab Allocator:An Object-Caching Kernel Memory Allocator](https://people.eecs.berkeley.edu/~kubitron/courses/cs194-24-S14/hand-outs/bonwick_slab.pdf)
4. [mm: SLUB freelist randomization](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=210e7a43fa905bccafa9bb5966fba1d71f33eb8b)
5. [mm: Add SLUB free list pointer obfuscation](https://patchwork.kernel.org/patch/9864165/)

6. [CVE-2016-6187: Exploiting Linux kernel heap off-by-one](http://cyseclabs.com/blog/cve-2016-6187-heap-off-by-one-exploit)
7. [Linux Kernel CAN SLUB Overflow](https://jon.oberheide.org/blog/2010/09/10/linux-kernel-can-slub-overflow/)
8. [Attacking the Core : Kernel Exploiting Notes](http://phrack.org/issues/64/6.html)


@sidebar(KASLR)
## Kernel Address Space Layout Randomization (KASLR)

Kernel Address Space Layout Randomization(KASLR) is a feature that randomize kernel location itself in order to mitigate known exploits which relies on predictable kernel addresses such as retrun-oriented-programming. KASLR implementation for x86-64 randomize three main memory regions : physical mapping, vmalloc and vmemmap. 

~~~
//@arch/x86/mm/kaslr.c

/*
 * Memory regions randomized by KASLR (except modules that use a separate logic
 * earlier during boot). The list is ordered based on virtual addresses. This
 * order is kept after randomization.
 */
static __initdata struct kaslr_memory_region {
	unsigned long *base;
	unsigned long size_tb;
} kaslr_regions[] = {
	{ &page_offset_base, 0 },
	{ &vmalloc_base, 0 },
	{ &vmemmap_base, 0 },
};

/* Get size in bytes used by the memory region */
static inline unsigned long get_padding(struct kaslr_memory_region *region)
{
	return (region->size_tb << TB_SHIFT);
}

....

void __init kernel_randomize_memory(void)
{
....
....
kaslr_regions[0].size_tb = 1 << (MAX_PHYSMEM_BITS - TB_SHIFT);
	kaslr_regions[1].size_tb = VMALLOC_SIZE_TB;

	/*
	 * Update Physical memory mapping to available and
	 * add padding if needed (especially for memory hotplug support).
	 */
	BUG_ON(kaslr_regions[0].base != &page_offset_base);
	memory_tb = DIV_ROUND_UP(max_pfn << PAGE_SHIFT, 1UL << TB_SHIFT) +
		CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING;

	/* Adapt phyiscal memory region size based on available memory */
	if (memory_tb < kaslr_regions[0].size_tb)
		kaslr_regions[0].size_tb = memory_tb;

	/*
	 * Calculate the vmemmap region size in TBs, aligned to a TB
	 * boundary.
	 */
	vmemmap_size = (kaslr_regions[0].size_tb << (TB_SHIFT - PAGE_SHIFT)) *
			sizeof(struct page);
	kaslr_regions[2].size_tb = DIV_ROUND_UP(vmemmap_size, 1UL << TB_SHIFT);
~~~
Above code calculate size of memory region in terabytes for physical mapping, vmalloc and vmemmap. Those size of memory region are used to calculate `remain_entropy` below.
~~~
	/* Calculate entropy available between regions */
	remain_entropy = vaddr_end - vaddr_start;
	for (i = 0; i < ARRAY_SIZE(kaslr_regions); i++)
		remain_entropy -= get_padding(&kaslr_regions[i]);

	prandom_seed_state(&rand_state, kaslr_get_random_long("Memory"));

	for (i = 0; i < ARRAY_SIZE(kaslr_regions); i++) {
		unsigned long entropy;

		/*
		 * Select a random virtual address using the extra entropy
		 * available.
		 */
		entropy = remain_entropy / (ARRAY_SIZE(kaslr_regions) - i);
		prandom_bytes_state(&rand_state, &rand, sizeof(rand));
		entropy = (rand % (entropy + 1)) & PUD_MASK;
		vaddr += entropy;
		*kaslr_regions[i].base = vaddr;

		/*
		 * Jump the region and add a minimum padding based on
		 * randomization alignment.
		 */
		vaddr += get_padding(&kaslr_regions[i]);
		vaddr = round_up(vaddr + 1, PUD_SIZE);
		remain_entropy -= entropy;
	}
}
~~~
In the last part of `kernel_randomize_memory()`, `remain_entropy` is initialized to available space of virtual memory. Actual randomization is done inside the for loop. Entropy is 'distributed' for each region and applied to their base. Note that it prevents monopoly of entropy by dividing `remain_entropy` to remain regions. `remain_entropy` is updated on each loop for the next region. 

### References
- [KASLR in the arm64 Linux kernel](http://www.workofard.com/2016/05/kaslr-in-the-arm64-kernel/)
