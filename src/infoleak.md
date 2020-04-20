@sidebar(Information Leaks)
# Preventing information leaks
@kconfig(CONFIG_HARDENED_USERCOPY)

## Hardening `usercopy()`

To prevent the leakage from the kernel objects,
the slab interface provides a way to specify the region
of each object that is allowed for usercopy.
For example, to protect `task_struct` from unintended leakage
(e.g., out-of-bound read beyond the usercopy region of the heap object),
a tuple of `useroffset` and `userisze` should be provided via
`kmem_cache_create_usercopy()`.

~~~~{.c}
void __init fork_init(void) {
  ...
  // NB. calculate the offset and size of the fpu states
  task_struct_whitelist(&useroffset, &usersize);
  task_struct_cachep = kmem_cache_create_usercopy("task_struct",
                         arch_task_struct_size, align,
                         SLAB_PANIC|SLAB_ACCOUNT,
                         useroffset, usersize, NULL);
}
~~~~

In `task_struct`, `fpu` state is allowed for usercopy (see, below),
which are accessed from/to via the `ptrace()` syscall.

~~~~{.c}
// @x86_64
//   task_struct_cachep->useroffset = 2624 :&fxregs_state
//   task_struct_cachep->usersize   =  960 :fpu_kernel_xstate_size

//
// arch_ptrace
// -> copy_regset_from_user
//   -> xfpregs_get()
//      -> user_regset_copyout()
//         -> copy_to_user()
int xfpregs_get(struct task_struct *target, const struct user_regset *regset,
                unsigned int pos, unsigned int count,
                void *kbuf, void __user *ubuf)
{
  struct fpu *fpu = &target->thread.fpu;
  ...
  return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
                             &fpu->state.fxsave, 0, -1);
}
~~~~

When `HARDENED_USERCOPY` enabled,
`copy_from/to_user` performs various sanity checks,
including the check for the `useroffset` and `usersize`.

~~~~{c.}
// copy_from/to_user()
//   -> check_object_size()
//     -> check_heap_object()
//       -> __check_heap_object()
void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
       bool to_user)
{
  struct kmem_cache *s;
  unsigned int offset;
  size_t object_size;

  /* NB. Fetch kmem_cache to find the object size/redzone. */
  s = page->slab_cache;

  /* NB. Reject if ptr is not possible to point to the page,
   * but the page is directly converted from ptr of its caller,
   * this path won't be taken in the current implementation. */
  if (ptr < page_address(page))
    usercopy_abort("SLUB object not in SLUB page?!", NULL,
             to_user, 0, n);

  /* Find offset within object. */
  offset = (ptr - page_address(page)) % s->size;

  /* Adjust for redzone and reject if within the redzone. */
  if (kmem_cache_debug(s) && s->flags & SLAB_RED_ZONE) {
    if (offset < s->red_left_pad)
      usercopy_abort("SLUB object in left red zone",
               s->name, to_user, offset, n);
    offset -= s->red_left_pad;
  }

  /* NB. Allow address range falling entirely within usercopy region.
  
   useroffset +   +-- offset (from ptr)
              |   v
              v   +--n-->|
              [   [      ]   ]
              |<--usersize--->|
   */
  if (offset >= s->useroffset &&
      offset - s->useroffset <= s->usersize &&
      n <= s->useroffset - offset + s->usersize)
    return;

  /*
   * If the copy is still within the allocated object, produce
   * a warning instead of rejecting the copy. This is intended
   * to be a temporary method to find any missing usercopy
   * whitelists.
   */
  object_size = slab_ksize(s);
  if (usercopy_fallback &&
      offset <= object_size && n <= object_size - offset) {
    usercopy_warn("SLUB object", s->name, to_user, offset, n);
    return;
  }

  usercopy_abort("SLUB object", s->name, to_user, offset, n);
}
~~~~

There are a few other similar mitigation schemes
to avoid such a mistake
when performing a `copy_to/from_user()`.
For example,
if an object is stack allocated,
then it checks if the object properly locates in the stack
as well as in the proper frame of the stack,
if the architecture provides a simple way
to walk the stack frames (e.g., frame pointer).

~~~~{.c}
// __check_object_size
//  -> check_stack_object
//    -> arch_within_stack_frames
static inline
int arch_within_stack_frames(const void * const stack,
                             const void * const stackend,
                             const void *obj, unsigned long len)
{
  const void *frame = NULL;
  const void *oldframe;

  // NB. return address of the caller
  oldframe = __builtin_frame_address(1);
  if (oldframe)
    // NB. return address of the caller's caller
    frame = __builtin_frame_address(2);

  /*
   * low ----------------------------------------------> high
   * [saved bp][saved ip][args][local vars][saved bp][saved ip]
   *                     ^----------------^
   *               allow copies only within here
   */
  while (stack <= frame && frame < stackend) {
    /*
     * If obj + len extends past the last frame, this
     * check won't pass and the next frame will be 0,
     * causing us to bail out and correctly report
     * the copy as invalid.
     */
    if (obj + len <= frame)
      // NB. 2 * sizeof(void*): frame pointer + return address
      return obj >= oldframe + 2 * sizeof(void *) ?
        GOOD_FRAME : BAD_STACK;
    oldframe = frame;
    frame = *(const void * const *)frame;
  }
  return BAD_STACK;
}
~~~~

## Restricting kernel pointers
@kconfig(CONFIG_SECURITY_DMESG_RESTRICT)

`dmesg` command prints debug messages of the kernel buffer. However, the kernel message buffer sometimes contains sensitive information such as register values which is not allowed to users. This makes much easier for an attacker makes an exploit as in CVE-2018-17182. Thus `DMESG_RESTRICT` prevents unprivileged users from viewing those messages using dmesg command. When `DMESG_RESTRICT` is enabled, only users with system administration privileges are  allowed to see the messages. When `DMESG_RESTRICT` is not enabled, every user can see the messages.  

`KPTR_RESTRICT` works as similar to `DMESG_RESTRICT`. Kernel pointer is another sensitive information that might have chances of using by malicious users. When `KPTR_RESTRICT` is set to 1, %pK format specifier hides kernel pointers to unprivileged users by printing 0s. When `KPTR_RESTRICT` is set to 0, %pK works as same as %p which means there is no restriction on printing pointers. When `KPTR_RESTRICT` is set to 2, %pK hides pointers regardless of privileges.

### References
- [STACKLEAK: A Long Way to the Linux Kernel Mainline](https://schd.ws/hosted_files/lssna18/b7/stackleak_LSS_NA_2018.pdf)
- [A pair of GCC plugins](https://lwn.net/Articles/712161/)
- [CVE-2018-17182: A Cache Invalidation Bug in Linux Memory Management](https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html)

