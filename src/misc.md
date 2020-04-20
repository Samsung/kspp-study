# Miscellaneous Topics

@sidebar(VLA)
## Eliminating Variable-length Arrays (VLA)

VLA allows programmers to specify the length of an array 
at runtime: 
e.g., using a variable instead of a constant 
for the array size.
This makes it easier to write certain types of programming logics 
such as packet/buffer handling or string manipulation, 
but has two critical problems, 
namely security and performance. 


~~~~{.c}
void test_vla(int i) {
  long buf[i];

  // => 30 instructions w/ div/mul
  // char *buf;
  // buf -= ((i << 0x3) + 0xf) / 0x10 * 0x10
}
~~~~

In terms of security, 
such a code pattern makes it hard 
to estimate the stack usage, 
otherwise incurring a stack clash in the kernel space.
Also, although often not emphasized enough,
this pattern 
makes it easier to exploit the uninitialized-use vulnerability: 
e.g., placing arbitrary data to the proper offset
of the kernel stack.
In terms of performance,
this benign looking code 
is translated to 
a set of about 30 native instructions 
that calculate the proper offset size 
and enforce alignment of the stack, 
otherwise incurring an exception 
in many architectures.
The translated instructions 
include a few computational intensive instructions 
such as `div` and `imul`,
so impose unwanted performance overheads
in a common path.
Since v4.20 [1], 
the compilation warning on the usage of VLA (i.e., `-Wvla`)
has been globally turned on; 
any use of VLA prevents 
the kernel from compilation,
thereby guiding developers to properly fix 
the use of VLA.

@sidebar(Fallthrough)
## Preventing mistakes in `switch/case`
The usage of `switch` `case` in C is rather error-prone:
an optional `break` statement can be used
in each `case` block to indicate the break 
of the logic, 
otherwise simply executing the next `case` block. 
As both usage patterns are prevalent,
it is hard to recognize
whether which one is intended code flow or not.
The most recent `break` mistake (04/2019 at the time of writing)
is in `sock_ioctl()` 
that is widely used and heavily audited function!

~~~~{.c}
// @net/socket.c
long sock_ioctl(struct file *file, unsigned cmd, unsigned long arg) {
...
    case SIOCGSTAMP_OLD:
    case SIOCGSTAMPNS_OLD:
      if (!sock->ops->gettstamp) {
        err = -ENOIOCTLCMD;
        break;
      }
      err = sock->ops->gettstamp(sock, argp,
               cmd == SIOCGSTAMP_OLD,
               !IS_ENABLED(CONFIG_64BIT));
+    break;
    case SIOCGSTAMP_NEW:
    case SIOCGSTAMPNS_NEW:
      ...
      break;
~~~~

To address this error-prone situation,
GCC introduces a compilation warning 
on an implicit use of case fall through 
(i.e., `-Wimplicit-fallthrough`):
to avoid the warning of the fall through case,
developers should _explicitly_ express 
the intention, either as a comment 
(`/* fall through */`) or 
as an attribute (`__attribute__((fallthrough))`).

~~~~{.diff}
+++ b/kernel/compat.c
@@ -346,8 +346,11 @@ get_compat_sigset(...)
                return -EFAULT;
        switch (_NSIG_WORDS) {
        case 4: set->sig[3] = v.sig[6] | (((long)v.sig[7]) << 32 );
+               /* fall through */
        case 3: set->sig[2] = v.sig[4] | (((long)v.sig[5]) << 32 );
+               /* fall through */
~~~~

@sidebar(Fortify)
## Fortify
@kconfig(CONFIG_FORTIFY_SOURCE)

FORTIFY_SOURCE was originally feature from gcc, but adopted to linux kernel later. This option provides support for detecting buffer overflows within various functions. Unfortunately, this option cannot detect all types of buffer overflows(will be discussed in below), but it is useful since it provides extra level of validation with low performance overhead. 
FORTIFY_SOURCE checks buffer overflow for functions below : 
~~~
memcpy, mempcpy, memmove, memset, strcpy, stpcpy, strncpy, strcat, 
strncat, sprintf, vsprintf, snprintf, vsnprintf, gets
~~~

Let's dive into some functions : strcpy() and memcpy().

At first, strcpy() checks object size via __butiltin_object_size(). This function returns object size that is determined on compile-time. However, if the object size is determined on run-time, e.g. object is allocated via kmalloc(), __butiltin_object_size() just returns -1. If both object size determined on run-time, strcpy() skips the overflow tests and passes objects to __builtin_strcpy(). Otherwise, it passes objects to memcpy() which is also fortified. Actual buffer-overflow checks would be done in memcpy(). As you can imagine, fortified strcpy() cannot detect buffer-overflows if size of both objects are determined on run-time, i.e. the case that strcpy passes objects to __builtin_strcpy().

~~~{.c}
/* defined after fortified strlen and memcpy to reuse them */
__FORTIFY_INLINE char *strcpy(char *p, const char *q)
{
	size_t p_size = __builtin_object_size(p, 0);
	size_t q_size = __builtin_object_size(q, 0);
	if (p_size == (size_t)-1 && q_size == (size_t)-1)
		return __builtin_strcpy(p, q);
	memcpy(p, q, strlen(q) + 1);
	return p;
}
~~~
memcpy() also checks object size via __butiltin_object_size(). Both read-overflow and write-overflow check are performed here. If no overflow detected, then it assumes overflow-safe and runs __builtin_memcpy().

~~~{.c}
__FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
{
	size_t p_size = __builtin_object_size(p, 0);
	size_t q_size = __builtin_object_size(q, 0);
	if (__builtin_constant_p(size)) {
		if (p_size < size)
			__write_overflow();
		if (q_size < size)
			__read_overflow2();
	}
	if (p_size < size || q_size < size)
		fortify_panic(__func__);
	return __builtin_memcpy(p, q, size);
}
~~~

### References

1. [VLA removal for v4.20-rc1](http://lkml.iu.edu/hypermail/linux/kernel/1810.3/02834.html)


@sidebar(Livepatch)
## Livepatch
@kconfig(CONFIG_LIVEPATCH)
Livepatch is a feature that applies kernel patches without any system reboot. There are many situations where systems have to keep running and up because of some critical issues such as huge economical costs. For example, In Facebook, it would take about over than 20 minutes to reboot for just one machine. But it is reluctant not to apply patches on kernel when some bugs were found as soon as possible. In order to meet these two requirements, livepatch gives the ways to redirect the buggy code to new code with keeping running.

### Consistency model
@assign(Sungbae Yoo)

### Design pattern for modules
@assign(Sungbae Yoo)

### How it works
@assign(Sungbae Yoo)

### Shadow data
@assign(Sungbae Yoo)

### Userspace tool(kpatch)
[Kpatch](https://github.com/dynup/kpatch) is a feature of the Linux kernel for livepatching made by Red Hat.  
kpatch-build is one of the kpatch modules that convert patch files into kernel module.
```c
+---------+    +---------------------+    +--------------+
| patch   |    | kpatch-build        |    | patch module |
+---------+ => | ============        | => +--------------+
| *.patch |    | Create patch module |    | *.ko         |
+---------+    +---------------------+    +--------------+
```

#### How to make kernel module
1.  Download and unpack kernel source matching with patches's distro.
2.  Test patch file with option [dry-run](https://www.gnu.org/software/diffutils/manual/html_node/Dry-Runs.html)
3.  Read special section data with command (readelf -wi "$VMLINUX")
	- alt_instr, bug_entry size,  jump_entry size ...
4. Build original source with compile options "-ffunction-sections and -fdata-sections"
5. Build patched source with compile options "-ffunction-sections and -fdata-sections"
6. Extract new and modified ELF sections
	- Compare #4's output and #5's output at a section level
	- Result: Elf object included {.kpatch.strings, .kpatch.symbols, .kpatch.relocations}
8. Build patch module with #6's output

#### Core data structure: [kpatch-elf]([https://github.com/dynup/kpatch/blob/master/kpatch-build/kpatch-elf.h](https://github.com/dynup/kpatch/blob/master/kpatch-build/kpatch-elf.h))
kpatch-build uses own data structure which added special data structures to elf format. The special data structures are able to include difference section between the origin object and the patched object.  
The intermediate objects of kpatch-build are used in the form of kpatch-elf.
```c
struct kpatch_elf {
  Elf *elf;
  struct list_head sections;
  struct list_head symbols;
  struct list_head strings;
  int fd;
};
```

#### Core module: [create-diff-object.c]([https://github.com/dynup/kpatch/blob/master/kpatch-build/create-diff-object.c](https://github.com/dynup/kpatch/blob/master/kpatch-build/create-diff-object.c))
This file contains the heart of the ELF object differencing engine.
- The tool takes two ELF objects from two versions of the same source file.
	-  a "base" object and a "patched" object
-  These object need to have been compiled with the GCC options.
	-  -ffunction-sections and -fdata-sections
- The tool compares the objects at a section level to determine what sections have changed.
- Once a list of changed sections has been generated, various rules are applied.

### References
1. [Kernel Live Patching: Consistency Model](https://lkml.org/lkml/2014/11/7/354)
2. [kpatch - live kernel patching](https://github.com/dynup/kpatch)
3. [Anatomy of kpatch](http://bitboom.github.io/anatomy-of-kpatch)
4. [An overview of kpatch-build](http://bitboom.github.io/kpatch-build-internal)
