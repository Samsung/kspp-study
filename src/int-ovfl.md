@sidebar(Integer Overflows)
# Mitigating Integer Overflows

@sidebar(Refcount)
## Preventing refcount overflows 
@kconfig(CONFIG_REFCOUNT_FULL)

A reference counter (i.e., `refcount`) can be overflowed if
incorrectly managed, resulting in a few dangling pointers. Such a
dangling pointer is relatively easy-to-exploit by leading it to a
use-after-free bug (e.g., inserting a fake object to the dangled
object via `msgsnd()`, see CVE-2016-0728).

In CVE-2016-0728, a keyring is not correctly freed when joining a
session keyring, and a function table pointing to `revoke()` in the
dangled object can hijacked, resulting in a privileged escalation.

If `REFCOUNT_FULL` is enabled, all `refcount_inc()` are replaced with a
below call. It checked two conditions: 1) if full then remained topped
(i.e., `UINT_MAX`) and continue to use the object (i.e., leak), and 2)
if freed then do not use the object. Similarly
`refcount_sub_and_test_checked()` checks a underflow condition.

~~~~{.c}
// @lib/refcount.c
bool refcount_inc_not_zero_checked(refcount_t *r) {
  unsigned int new, val = atomic_read(&r->refs);
  do {
    new = val + 1;
    if (!val)		// NB. refcount is already freed
      return false;
    if (unlikely(!new)) // NB. refcount is overflowed
      return true;
  } while (!atomic_try_cmpxchg_relaxed(&r->refs, &val, new));
  return true;
}
~~~~

__Optimization.__ `PAX_REFCOUNT` and [2] propose a potential
optimization by trading #refcount by a half, using a sign bit to
indicate overflowed condition. However, the current implementation
just uses a `cmpxchg()` with an explicit check of an overflow and
use #refcount upto `UINT_MAX`.

~~~~{.S}
lock incl -0xc(%rbp)
js overflowed ; NB. unlikely to be taken

overflowed:
lea -0xc(%rbp),%rcx ; NB. restored to an old refcount
<UD0>
~~~~

### Performance implication
TODO.

### References
1. [CVE-2016-0728: PoC exploit](https://perception-point.io/resources/research/analysis-and-exploitation-of-a-linux-kernel-vulnerability/)
2. [Implement fast refcount overflow protection](https://lwn.net/Articles/724206/)

@sidebar(Safe Interfaces)
## Tools to prevent integer overflows

Developers have detected integer overflows as the following:

~~~~{.c}
x + y < x //for addition
x - y > x //for substraction
x != 0 && y > c/x //for multiplication
~~~~

There are a few problems with the above techniques.
In case of signed integers, it cannot guarantee the complete checking 
because it relies on undefined behavior.

Therefore, GCC5 has introduced built in macros to check for
integer overflows without undefined behavior.
For example, overflows in signed integers are detected like below.

~~~~{.c}
// @include/linux/overflow.h
#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))


/* Checking for unsigned overflow is relatively easy without causing UB. */
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})


/*
 * Adding two signed integers can overflow only if they have the same
 * sign, and overflow has happened iff the result has the opposite
 * sign.
 */
#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})

~~~~


### Performance implication

### References
1. [compiler: use compiler to detect integer overflows](https://lwn.net/Articles/623368/)
