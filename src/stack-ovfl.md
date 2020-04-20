@sidebar(Stack Overflows)
# Mitigating Stack Overflows

When a stack is overflowed, an attacker has a chance to overwrite a
security-critical data structure located in another task's stack. For
example, `thread_info` traditionally locates at the bottom of the
stack, which one long-size overflow can overwrite to. By overwriting
the `thread_info`, an attacker can escalate its privilege by
overwriting the `cred` structure.

@sidebar(Stack Clash)
## Preventing stack clash
@kconfig(CONFIG_VMAP_STACK)

Using virtually-mapped (vmap) stacks has two benefits: 1) flexible in
allocating larger, non-continuous pages, 2) preventing a potential
stack overflow by placing one guard page between vmapped regions. Such
a guard page can mitigate a stack clash that is overwritten by another task,
if consequently located. As virtually mapped, the guard page
won't be wasting any real page unlike `kmalloc()`-based stack.

~~~~{.c}
// @kernel/fork.c
alloc_thread_stack_node()
  -> __vmalloc_node_range()
     -> __get_vm_area_node()

    // by default, vmap_area includes one more page as a guard
    if (!(flags & VM_NO_GUARD))
      size += PAGE_SIZE;
~~~~

The way the kernel handles a stack overflow is pretty
interesting. When the kernel mode touches a guard page, it generates a
page fault, so its handler specifically checks such a condition like below.

~~~~{.c}
// @arch/x86/mm/fault.c
// do_page_fault()
//   -> __do_page_fault()
//      -> do_kern_addr_fault()
//         -> bad_area_nosemaphore()
//            -> __bad_area_nosemaphore()
static noinline void
no_context(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, int signal, int si_code)
{
...
  if (is_vmalloc_addr((void *)address) &&
       (((unsigned long)tsk->stack - 1 - address < PAGE_SIZE) ||
         address - ((unsigned long)tsk->stack + THREAD_SIZE) < PAGE_SIZE)) {

    // NB. as the stack is likely out-of-space, use the stack for double-fault
    unsigned long stack = __this_cpu_ist_top_va(DF) - sizeof(void *);

    // NB. invoke handle_stack_overflow() to inform an oops.
    asm volatile ("movq %[stack], %%rsp\n\t"
                   "call handle_stack_overflow\n\t"
                   "1: jmp 1b"
                   : ASM_CALL_CONSTRAINT
                   : "D" ("kernel stack overflow (page fault)"),
                     "S" (regs), "d" (address),
                   [stack] "rm" (stack));
     unreachable();
  }
...
}
~~~~

It's likely that the page fault handler touches the guard page,
_again_ as we are running out of the stack space, which generates a
double-fault.

~~~~{.c}
// @arch/x86/kernel/traps.c
void do_double_fault(struct pt_regs *regs, long error_code)
{
...
  cr2 = read_cr2();
  if ((unsigned long)task_stack_page(tsk) - 1 - cr2 < PAGE_SIZE)
    handle_stack_overflow("kernel stack overflow (double-fault)", regs, cr2);
...
}
~~~~

One difference is that the page fault handler checks one page
before/after the stack, but the double-fault handler checks only the
overflow (when growing downward). This likely misdiagnoses the
condition for `STACK_GROWSUP` yet rarely used in practice.

__Related CVEs.__ Numerous CVEs (e.g., CVE-2016-10153, CVE-2017-8068,
CVE-2017-8070, etc) relevant to `VMAP_STACK` are recently assigned due
to its implication of DoS or potential memory corruption (unlikely
controllable). The basic idea is that during iterating the
scatter-gather list by a DMA engine, the stack-allocated, vmapped
buffer is unlikely physically contiguous across the page
boundary, potentially overwriting irrelevant page. It's unlikely that
the buffer is large enough to cross the page boundary, otherwise
a developer allocated DMA-able region at the first place. One caveat
however was that under a certain condition
(e.g., `DEBUG_VIRTUAL`), `__phys_addr()` can trigger `BUG()`
when the provided address is `vmalloc()`-region, resulting in a DoS.


### Performance implication
| | VMAP=n| VMAP=y, #C=0 |#C=2|#C=3|#C=5|
|:--------|--------:|--------:|--------:|--------:|--------:|
| **kbuild(seconds)** | 27.648798683 | - | 27.545090630 | - | - |
| **iterations, cpu 0** | 106343 | 99673 | 101130 | 100568 | 100025 |
| **iterations, cpu 2** | 118526 | 93372 | 119380 | 117901 | 116726 |
| **iterations, cpu 7** | 117700 | 94010 | 117651 | 117719 | 115385 |

The table above shows thread performance results measured using microbenchmarks.
The higher the number of iterations, It means the faster the performance.
And #C means number of cache entries.

Allocating a stack from the vmalloc area, makes creating a process
with `clone()` take about 1.5µs longer.[1] So for fixing this problem,
caching two thread stacks per cpu was introduced.[4]

Thread performance is slower when using virtual mapped stacks.
and the performance is affected by number of cache entries.
Currently, the number of cache entries is two, and if it is increased than two,
the performance is slower a bit. And if `CONFIG_VMAP_STACK` set when kernel build,
it is about 0.1 seconds faster then without `CONFIG_VMAP_STACK`.
So It's better using `CONFIG_VMAP_STACK` and two cache entries can complement
the performance.

### References
1. [LWN: Virtually mapped kernel stacks](https://lwn.net/Articles/692208/)
2. [CVE-2016-1583: Exploiting Recursion in the Linux Kernel](https://googleprojectzero.blogspot.com/2016/06/exploiting-recursion-in-linux-kernel_20.html)
3. [Mailing: Can someone explain all the CONFIG_VMAP_STACK CVEs lately?](https://lwn.net/Articles/726593/)
4. [fork: Cache two thread stacks per cpu if CONFIG_VMAP_STACK is set](https://patchwork.kernel.org/patch/9199707/)


@sidebar(Hardening thread_info)
## Protecting `thread_info`
@kconfig(CONFIG_THREAD_INFO_IN_TASK)

Hijacking `thread_info` or `task_struct` is a straight way to achieve
a privilege escalation: overwriting its `uid` to the root's, zero. As
they are used to locate at the bottom of the stack (e.g.,
`task_struct` in <2.6 or `thread_info` in later versions), bugs such
as stack clash, stack overflow, or arbitrary write after a stack
pointer leak, can launch an exploit against them.

An easy mitigation is to completely remove them from the stack:
THREAD_INFO_IN_TASK, as its name implicates, embeds `thread_info` into
`task_struct`. Since the `current` task can be accessed with per-cpu
data structure, `thread_info` can be accessed with one additional
memory access. Note that `thread_info` is supposed to contain the
architecture-specific information and `task_struct` does for
architecture-neutral data. The current effort in x86 virtually
migrates all information to the `task_struct`.

~~~~{.c}
// @include/linux/sched.h
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
  /*
   * For reasons of header soup (see current_thread_info()), this
   * must be the first element of task_struct.
   */
   struct thread_info thread_info;
#endif
...
}
~~~~

The bottom of the stack contains `thread_info` if not
THREAD_INFO_IN_TASK, which is protected by a magic value,
`STACK_END_MAGIC` that shouldn't be considered as security enhancement
or mechanism. `end_of_stack()` simply returns the usable stack region
and handles both situation seamlessly.

~~~~{.c}
// @include/linux/sched/task_stack.h
void set_task_stack_end_magic(struct task_struct *tsk)
{
  unsigned long *stackend;
  stackend = end_of_stack(tsk);

  // NB. indicating that current stack is overwritten by an overflow
  *stackend = STACK_END_MAGIC;
}

#ifdef CONFIG_THREAD_INFO_IN_TASK
unsigned long *end_of_stack(const struct task_struct *task)
{
  return task->stack;
}
// NB. thread_info will be copied as part of task_struct
#define setup_thread_stack(new,old) do { } while(0)

#else
unsigned long *end_of_stack(struct task_struct *p)
{
  return (unsigned long *)(task_thread_info(p) + 1);
}
void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
  // NB. copied to the stack end (top)
  *task_thread_info(p) = *task_thread_info(org);
  task_thread_info(p)->task = p;
}
#endif
~~~~

### Performance implication
- don't expect much


@sidebar(SSP)
## Stack canary (SSP)
FIX. config in 4.15 is named differently
@kconfig(CONFIG_STACKPROTECTOR_STRONG)

### Performance implication

--------------------------------------------------------------------------------
Option                   Size (KB)               Protected functions
------------------------ ------------ -------- --------------------- -----------
None                     53,519 KB                          0/48,606     

STACKPROTECTOR           53,490 KB    (-0.05%)          1,390/48,607    (+2.86%)

STACKPROTECTOR_STRONG    55,312 KB    (+3.35%)          9,922/48,608   (+20.41%)
--------------------------------------------------------------------------------

`STACKPROTECTOR_STRONG` inserts a canary to 20% of functions in the
kernel, unlike `STACKPROTECTOR` protects 3%, resulting in about 3%
increment of the binary size. For example, `bstat()` is newly
protected with `STACKPROTECTOR_STRONG` as it has `struct kstat` as a
local variable.

What's interesting is the binary size of `STACKPROTECTOR` compared
with the unprotected binary: inserting canary indeed reduces the
binary size. According to our analysis, checking canary at the
epilogue tends to encourage the reuse of common gadgets (e.g., `pop` or
`ret`) at exit paths, rendering better utilization of instructions.

### References
- [Google: New stack protector option for gcc](https://docs.google.com/document/d/1xXBH6rRZue4f296vGt9YQcuLVQHeE516stHwt8M9xyU/edit)
- [LWN: "Strong" stack protection for GCC](https://lwn.net/Articles/584225/)
