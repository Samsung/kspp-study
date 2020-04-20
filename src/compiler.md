@sidebar(GCC Plugins)
# Compiler-based Security Checkers

@sidebar(Information Leak Prevention)
## Preventing information leaks
@kconfig(GCC_PLUGIN_STACKLEAK)
@kconfig(GCC_PLUGIN_STRUCTLEAK_USER)
@kconfig(GCC_PLUGIN_STRUCTLEAK_BYREF)
@kconfig(GCC_PLUGIN_STRUCTLEAK_BYREF_ALL)
@kconfig(INIT_STACK_ALL)

__Stackleak Plugin.__

There are three kinds of vulnerabilities that STACKLEAK kernel security feature
wants to defend against: 1) Information disclosure coming frome leaving data on 
the stack that can be exfiltrated to user space, 2) Targeting Uninitialized 
variable on the kernel stack to get the stack location, and 3) Stack clash.

The first two of the vulnerabilities are closely related. Chaining attacks 
like getting information from left over values on the stack and targeting the 
address could happen. These two vulnerabilities are blocked by the feature 
called `stack poisoning`. This feature overwrites STACKLEAK_POISON(-0xBEEF) to 
the used portion of the stack at the end of the syscall, before returning to 
the caller. Below is the implementation of stack poisoning. This code checks 
the count of unpoisoned space in the kernel stack, and then fills the
STACKLEAK_POISON value from the lowest boundary of the current used stack.


~~~~{.c}
asmlinkage void stackleak_erase(void)
{
    unsigned long kstack_ptr = current -> lowest_stack;
    unsigned long boundary = (unsigned long)end_of_stack(current);
    unsigned int poison_count = 0;
    const unsigned int depth = STACKLEAK_SEARCH_DEPTH / sizeof(unsigned long);

    if (skip_erasing())
        return;

    while (kstack_ptr > boundary && poison_count <= depth) { 
        if (*(unsigned long *)kstack_ptr == STACKLEAK_POISON)
            poison_count++;
        else
            poison_count = 0;

        kstack_ptr -= sizeof(unsigned long);
    }

    if (kstack_ptr == boundary)
        kstack_ptr += sizeof(unsigned long);

    ...
    if (on_thread_stack())
        boundary = current_stack_pointer;
    else
        boundary = current_top_of_stack();

    while (kstack_ptr < boundary) {
        *(unsigned long *)kstack_ptr = STACKLEAK_POISON;
        kstack_ptr += sizeof(unsigned long);
    }

    current->lowest_stack = current_top_of_stack() - THREAD_SIZE/64;
}

~~~~



Stack poisoning prevents the stack from leaving space to be exposed, but it 
only works for multi-system-call attacks; it cannot protect against attacks 
that complete during a single system call, since the stack poisoning is done at 
the end of the system call. And one more, since the stack poison value could be 
a valid pointer to the stack since the user space address range from 0x0000 to
0x0fff and the kernel space address range from 0xf000 to 0xffff.


The third vulnerability, stack clash, is about prohibiting the memory region. 
It includes clashing the stack with another memory region, jumping over the 
stack guard page, and smashing the stack(overwriting the stack with other memory 
region). When the stack is full, it is automatically extended by using the page 
fault. If the end of the current stack access to the already allocated page, 
page fault will not happen and kernel cannot notice that they have reached the 
stack's end so the stack clash would happen.


Usually, variable length array like alloca() function call is used to consume 
the stack's allocated space. So the STACKLEAK plugin tried to prevent stack 
clash by checking all the alloca() calls using panic() and BUG_ON() function. 
Now Stack-poisoning is included in linux kernel mainline, but alloca() checking 
has been dropped since it is believed that all VLAs are removed instead.

__Structleak Plugin.__

There are many structures that are not initialized in kernel code. This may have 
interesting values from kernel when copied to user space without initialization. 
One example arised in CVE-2013-2141. According to CVE-2013-2141 report, `do_tkill`
function in kernel/signal.c before kernel 3.8.9 did not initialize a data structure 
variable `siginfo`. The function `do_tkill` is called in system calls tkill and tgkill 
which can be invoked by user-level processes. When handling signals delivered 
from tkill, kernel memory is visible. 

Structleak plugin resolves this issue by initializing uninitialized structures 
in the kernel. After gcc finishes type parsing, plugin is invoked. The plugin 
currently has three modes: Disabled, BYREF and `BYREF_ALL`. When BYREF is marked, 
the plugin initializes structures which may had passed by reference and had not 
been initialized. When `BYREF_ALL` is marked, the plugin initializes any stack 
variables passed by reference. 

First, `PLUGIN_FINISH_TYPE` callback is called after finishing parsing type of code. 
Function finish_type()  sets `TYPE_USERSPACE` on structure variables of interests 
which have `__user` attribute on declaration.  

~~~~{.c}
static bool is_userspace_type(tree type)
{
	tree field;

	for (field = TYPE_FIELDS(type); field; field = TREE_CHAIN(field)) {
		tree fieldtype = get_field_type(field);
		enum tree_code code = TREE_CODE(fieldtype);

		if (code == RECORD_TYPE || code == UNION_TYPE)
			if (is_userspace_type(fieldtype))
				return true;

		if (lookup_attribute("user", DECL_ATTRIBUTES(field)))
			return true;
	}
	return false;
}

~~~~

After some declarations are marked as interests, structleak_execute() is executed. 
Execution function iterates all local variables and initialize the targets. Execeptions are 
auto variables (local variables which are stored in stack region), record or union types 
unless `BYREF_ALL` is set. If the local declaration is type of our interest(user annotated), 
or addressable structures with BYREF set, plugin call initialize functions. 

~~~~{.c} 
static unsigned int structleak_execute(void)
{
    ...

	/* enumerate all local variables and forcibly initialize our targets */
	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree type = TREE_TYPE(var);

		gcc_assert(DECL_P(var));
		if (!auto_var_in_fn_p(var, current_function_decl))
			continue;

		if (byref != BYREF_ALL && TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE)
			continue;

		if (TYPE_USERSPACE(type) ||
		    (byref && TREE_ADDRESSABLE(var)))
			initialize(var);
	}

	return ret;
}
~~~~

However, the plugin has false positive problems because `__user` attribute is just for kernel 
static analysis tool such as Sparse, but not an true indication of pointers whether the pointer will 
be copied to user space or not. Conversely, there might be another pointers 
without `__user` attribute but copied to user space. 

PaX team, who originally proposed the plugin, are aware of the false positive problems and 
suggests better solutions to analyzing calls to copy_to_user(). 
But it seems that they do no longer pay attention to this problem since the original problem CVE-2013-2141 is solved. 

Since the plugin initializes structrues passed by reference if `BYREF` is set as stated 
in the function structleak_execute(), it is highly suggested to set `BYREF` or `BYREF_ALL` 
when using this plugin to make it work as expected. 


@sidebar(Kernel Structure Attack Mitigation)
## Randomizing kernel data structures
@kconfig(GCC_PLUGIN_RANDSTRUCT)
@kconfig(GCC_PLUGIN_RANDSTRUCT_PERFORMANCE)

There are lots of juicy target members for attackers in kernel structures
(struct or union), for example, function pointers, stack pointers, process
credentials, and important flags etc.. Attackers usually try to trick kernel
into executing their exploit code by overwriting such members in structures.

__Randstruct plugin.__
In order to mitigate such attacks, `Randstruct` plugin randomizes structure
layout at compile time. Once structure layout is randomized, it will be much
harder for attackers to overwrite specific members of those structure since
they now do not know the layout of the structure.

`Randstruct` plugin works in three steps:
1) Detect structure to randomize.
2) Randomize layout of the structure.
3) Find bad casts from/to randomized structure pointer and notify it.

_Note: Step 3 works after step 1 and 2 are done for all structures._
<br />
<br />
<br />
Let's see what it does at each step with code.

__1. Detection.__

When detecting target structure, plugin picks the structure marked with
"__randomize_layout" attribute on its declaration, or the structure which
contain only function pointers automatically.

~~~{.c}
static int is_pure_ops_struct(const_tree node)
{
...
  (Return 1 if the structure contains only function pointers.)
  (There was a bug here which could cause false negative, and we patched it.)
  (See `Bug patch` below.)
...
}

static void randomize_type(tree type)
{
...
  if (lookup_attribute("randomize_layout", TYPE_ATTRIBUTES(TYPE_MAIN_VARIANT(type))) || is_pure_ops_struct(type))
    relayout_struct(type);
...
}
~~~

__2. Randomization.__

Once it has picked the target structure, it randomizes the position of fields
with modern in-place Fisher-Yates shuffle algorithm. If the target structure
has flexible array member, however, the plugin does not randomize the member
(field).

~~~{.c}
static int relayout_struct(tree type){
...
  /*
   * enforce that we don't randomize the layout of the last
   * element of a struct if it's a 0 or 1-length array
   * or a proper flexible array
   */
  if (is_flexible_array(newtree[num_fields - 1])) {
    has_flexarray = true;
    shuffle_length--;
  }

  shuffle(type, (tree *)newtree, shuffle_length);
...
}
~~~

__3. Bad casts notification.__

@todo(More explanation and code review.)

### References
- [Check member structs in is_pure_ops_struct()](https://kernel.googlesource.com/pub/scm/linux/kernel/git/next/linux-next/+/60f2c82ed20bde57c362e66f796cf9e0e38a6dbb)
- [Randomizing structure layout](https://lwn.net/Articles/722293/)
- [Introduce struct layout randomization plugin](https://lwn.net/Articles/719732/)
