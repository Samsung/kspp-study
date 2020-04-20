@sidebar(Side-channel Attacks)
# Mitigating Microarchitecture Side-channel

@sidebar(Meltdown)
## Mitigating KASLR and Meltdown
@kconfig(CONFIG_PAGE_TABLE_ISOLATION)

Mapping both user-space and kernel-space in one page-table
takes a lot of advantages to the linux kernel.
But on the other side, it has negative impact on security.
Many researchers have exploited that for a profit
via a variety of side channels.
It allows an attacker to bypass KASLR, even worse,
to read kernel memory from user-space
that is known as Meltdown.
So the linux kernel ended up to isolate the page-table
based on its execution mode, either user or kernel.
That is dubbed as page table isolation or pti.
The implementation of pti is straightforward.
allocate two page tables for a process,
one is for user mode, another one is for kernel mode,
and kernel mode can see entire memory space,
on the other hand,
user mode is limited not to see kernel space.
It effectively closes both KASLR-attacks and Meltdown.

Allocating two page tables in a contiguous area.

~~~~{.c}
// arch/x86/include/asm/pgalloc.h
// #ifdef CONFIG_PAGE_TABLE_ISOLATION
// #define PGD_ALLOCATION_ORDER 1
// #else
// #define PGD_ALLOCATION_ORDER 0
// #endif
....
....
// arch/x86/mm/pgtable.c
static inline pgd_t *_pgd_alloc(void)
{
  return (pgd_t *)__get_free_pages(PGALLOC_GFP, PGD_ALLOCATION_ORDER);
  // NB. CONFIG_PAGE_TABLE_ISOLATION --> 8kb, two page tables.
  // !CONFIG_PAGE_TABLE_ISOLATION --> 4kb, one page table.
}
~~~~

Locating the page table at a syscall entry,
either user-to-kernel or kernel-to-user.

~~~~{.c}
ENTRY(entry_SYSCALL_64)
    UNWIND_HINT_EMPTY

    swapgs
    // NB. percpu-access before SWITCH_TO_KERNEL_CR3
    // the percpu-area should be mapped in user page table.
    movq    %rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
    // NB. locating the page table, user-to-kernel.
    SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
    movq    PER_CPU_VAR(cpu_current_top_of_stack), %rsp
~~~~

As shown in above code,
the kernel entry code accesses per-cpu areas before
locating the page table.
So the per-cpu areas are needed to be mapped
in the page table for user mode.

~~~~{.c}
static void __init setup_cpu_entry_area(unsigned int cpu)
{
....
....
// NB. create a mapping for per-cpu areas
 cea_set_pte(&cea->gdt, get_cpu_gdt_paddr(cpu), gdt_prot);

    cea_map_percpu_pages(&cea->entry_stack_page,
                 per_cpu_ptr(&entry_stack_storage, cpu), 1,
                 PAGE_KERNEL);
....
 cea_map_percpu_pages(&cea->tss, &per_cpu(cpu_tss_rw, cpu),
                 sizeof(struct tss_struct) / PAGE_SIZE, tss_prot);
}
....
....
void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags)
{
    unsigned long va = (unsigned long) cea_vaddr;
    pte_t pte = pfn_pte(pa >> PAGE_SHIFT, flags);

    // NB. _PAGE_GLOBAL indicates a mapping for all page tables
    // including both user and kernel.
    if (boot_cpu_has(X86_FEATURE_PGE) &&
        (pgprot_val(flags) & _PAGE_PRESENT))
        pte = pte_set_flags(pte, _PAGE_GLOBAL);
~~~~

Lastly, the pti leverages PCID or Process Context IDentifier
to avoid a TLB collision between user-space and kernel-space.
It works by assigning a different PCID to each execution mode.
With this hardware support of Intel,
the pti has a negligible performance impact.

~~~~{.c}
.macro ADJUST_KERNEL_CR3 reg:req
    ALTERNATIVE "", "SET_NOFLUSH_BIT \reg", X86_FEATURE_PCID
    // NB. CR3 register contains an address of page table.
    // Since the lowest 12 bits are unused, (page-aligned)
    // they are used to represent a PCID.
    andq    $(~PTI_USER_PGTABLE_AND_PCID_MASK), \reg
.endm

.macro SWITCH_TO_KERNEL_CR3 scratch_reg:req
    ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_PTI
    mov %cr3, \scratch_reg
    ADJUST_KERNEL_CR3 \scratch_reg
    mov \scratch_reg, %cr3
.Lend_\@:
.endm
~~~~

### References
1. [KASLR is Dead: Long Live KASLR](https://gruss.cc/files/kaiser.pdf)
2. [Meltdown: Reading Kernel Memory from User Space](https://meltdownattack.com/meltdown.pdf)
1. [Side Channel Attacks on Linux Kernel](https://jinb-park.blogspot.com/2019/06/side-channel-attacks-on-linux-kernel.html)
2. [Deep dive into Page Table Isolation](https://jinb-park.blogspot.com/2019/06/deep-dive-into-page-table-isolation.html)
3. [Deep dive into Defense against BTB attacks](https://jinb-park.blogspot.com/2019/06/deep-dive-into-defense-against-btb.html)

@sidebar(Spectre)
## Mitigating Spectre
@kconfig(CONFIG_RETPOLINE)

Modren CPUs have a branch predictor
to optimize their performance.
It works by referencing Branch Target Buffer or BTB
that is a storage for a key(PC)-value(Target PC) pair.
But its size limitation causes a BTB collision
that leads to a new side-channel attack.
The root cause of the attack is that
BTB stores some parts of the bits of PC,
not the full bits of PC.
Using this primitive, an attacker is able to inject
an indirect branch target into the BTB,
and consequently run some codes in a speculative context.
It can leak a sensitive data across some boundaries.
(e.g. between VMs, Processes, ...)
The attack is called Spectre Variant2.
and retpoline has been introducted to stop the attack.
The concept of retpoline is straightforward,
but the implementation is a little tricky.
Retpoline aims to eliminate all speculating behaviors
that can be controlled by an attacker.

Indirect jump replacement with Retpoline.
Take a look at how to implement
an indirect branch with no speculation.

~~~~{.c}
// Before Retpoline
jmp *%rax

// After Retpoline
(1) call load_label
    capture_ret_spec:
(2) pause; LFENCE
(3) jmp capture_ret_spec
    load_label:
(4) mov %rax, (%rsp)
(5) ret

// NB. Let's follow a Retpoline gadget.
// two executions are performing in parallel.
// o: original execution
// s: speculative execution
// (1-o) Direct branch to (4).
//     Push (2) onto the stack as a return.
// (4-o) Overwrite the return with the real target.
// (5-o) Load the real target from the stack memory.
// (5-s) If speculating here by RSB (Return Stack Buffer),
//     consumes RSB entry created in (1-o),
//     jumps to (2)
// (2-s) relaxing cpu for the spin-wait loop.
// (3-s) jumps to (2) again.
//     it forces the speculative execution
//     not be outside of (2)-(3).
// (5-o) Jump to the real target.
// --> There are no speculation!
~~~~

The linux kernel supports Retpoline
as an alternaitve section, which means that
an admin can determine to enable/disable retpoline
when boot-time via a kernel command-line.

~~~~{.c}
// NB. A retpoline gadget replacing an indirect branch.
.macro RETPOLINE_JMP reg:req
 call    .Ldo_rop_\@
.Lspec_trap_\@:
 pause
 lfence
 jmp .Lspec_trap_\@
.Ldo_rop_\@:
 mov \reg, (%_ASM_SP)
 ret
.endm

.macro JMP_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
// NB. register an indirect branch as an alternative insn.
    ANNOTATE_NOSPEC_ALTERNATIVE
    ALTERNATIVE_2 __stringify(ANNOTATE_RETPOLINE_SAFE; jmp *\reg),  \
        __stringify(RETPOLINE_JMP \reg), X86_FEATURE_RETPOLINE, \
        __stringify(lfence; ANNOTATE_RETPOLINE_SAFE; jmp *\reg), X86_FEATURE_RETPOLINE_AMD
#else
    jmp *\reg
#endif
.endm

void __init alternative_instructions(void)
{
  ...
  // NB. runtime patching to apply retpoline gadgets.
  // (__alt_instructions ~ __alt_instructions_end) includes
  // a lot of sites for indirect branches.
  apply_alternatives(__alt_instructions, __alt_instructions_end);
  ...
}
~~~~

__MDS (Microarchitectural Data Sampling).__

When performing store, load, L1 refill,
processors write data into a variety of temporary buffers
defined by microarchitecture such as
Load Buffer, Store Buffer, Line Fill Buffer.
The data in the buffers can be forwarded to load operations
as an optimization.
Unfortunately this kind of forwarding can across boundary,
which means a kernel data can be forwarded to a load operation
inside user space.
If an attacker can stick the data
into a leak gadget inside user space,
it eventually leaks a kernel memory.
The mitigation against this attack is very straightforward.
It's to clear the cpu buffers when returning to user.

~~~~{.c}
static inline void mds_clear_cpu_buffers(void)
{
    static const u16 ds = __KERNEL_DS;
    ....
    asm volatile("verw %[ds]" : : [ds] "m" (ds) : "cc");
}

static inline void mds_user_clear_cpu_buffers(void)
{
    if (static_branch_likely(&mds_user_clear))
        mds_clear_cpu_buffers();
}

__visible inline void prepare_exit_to_usermode(struct pt_regs *regs)
{
    ....
    // NB. When returning from kernel to user,
    // it clears cpu buffers that contain in-fligt data.
    mds_user_clear_cpu_buffers();
}
~~~~

__L1TF - L1 Terminal Fault.__
L1TF is a hardware vulnerability which allows
unprivileged speculative access to data
in the Level 1 Data Cache.
The root cause in it is that
a physical address in a PTE (page table entry) could be
speculative accessed despite the PTE is invalid
when peforming page table walk.

Linux kernel applies PTE inversion to
some codes relevant to page table maintenance.
That modifies PTE to make sure that
a physical address in a invalid PTE
always points to invalid physical memory.
This is an unconditional defense.

~~~~{.c}
// PTE inversion

static inline bool __pte_needs_invert(u64 val)
{
    // NB. PTE is exist, but invalid.
    return val && !(val & _PAGE_PRESENT);
}

static inline u64 protnone_mask(u64 val)
{
    // NB. If PTE inversion needed,
    // return the mask for PTE to point to invalid memory.
    return __pte_needs_invert(val) ?  ~0ull : 0;
}

static inline unsigned long pte_pfn(pte_t pte)
{
    phys_addr_t pfn = pte_val(pte);
    // NB. Masking PFN (physical address)
    // after masking, it's pointing to invalid memory.
    pfn ^= protnone_mask(pfn);
    return (pfn & PTE_PFN_MASK) >> PAGE_SHIFT;
}
~~~~

### References
1. [More details about mitigations for the CPU Speculative Execution issue](https://security.googleblog.com/2018/01/more-details-about-mitigations-for-cpu_4.html)
2. [Retpoline: a software construct for preventing branch-target-injection](https://support.google.com/faqs/answer/7625886)
3. [Spectre Returns! Speculation Attacks using the Return Stack Buffer](https://www.usenix.org/system/files/conference/woot18/woot18-paper-koruyeh.pdf)
4. [MDS - Microarchitectural Data Sampling](Documentation/admin-guide/hw-vuln/mds.rst)
5. [L1TF - L1 Terminal Fault](Documentation/admin-guide/hw-vuln/l1tf.rst)
6. [Meltdown strikes back: the L1 terminal fault vulnerability](https://lwn.net/Articles/762570/)
