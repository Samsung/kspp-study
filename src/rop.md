@sidebar(Code Reuse Attack)
# Preventing Code Reuse Attack

The System programming languages such as C and C++ give a freedom to optimize
and control their resource. It requires the programmer to manually manage
memory and observe typing rules leads to security vulnerabilities.<br>
Memory corruptions are routinely exploited by attackers. Following defenses are
introduced to mitigate such attacks:
* Address Space Layout Randomization (ASLR)
* Stack canaries
* Data Execution Prevention (DEP)

They protects against **code injection** attack, but not fully prevent
**code reuse** attack, e.g. ROP.

## Return Oriented Programming (ROP)
In a ROP attack, the attacker does not inject new code; instead, the malicious
computation is performed by chaining together existing sequences of instructions
(called gadgets).

~~~
        Stack                     Instructions
 +-----------------+
 |                 | ----------->  pop eax
 |-----------------|        /----  ret
 |       v1        |       /
 |-----------------| <----/
 |                 | ----------->  pop ebx
 |-----------------|        /----  ret
 |       v2        |       /
 |-----------------| <----/
 |                 | ----------->  add eax, ebx
 |                 |       /-----  ret
 |-----------------| <----/
 |                 | ----------->  pop ecx
 |-----------------|        /----  ret
 |       v3        |       /
 |-----------------| <----/
 |                 | ----------->  mov [ecx], eax
 +-----------------+               ret

 -> Result: mem[v3] = v1 + v2
~~~

The attacker finds gadgets within the original program text and causes them
to be executed in sequence to perform a task other than what was intended.
Common objectives of such malicious payloads include arbitrary code execution,
privilege escalation, and exfiltration of sensitive information.<br>
Many ROP attacks use unintended instruction sequences. CFI mitigates such
attacks by guaranteeing the program is in intended execution flow.

## Control Flow Integrity (CFI)

CFI is to restrict the set of possible control-flow transfers to those that are
trictly required for correct program execution. This prevents code-reuse
techniques such as ROP from working because they would cause the program to
execute control-flow transfers which are illegal under CFI.<br>
Most CFI mechanisms follow a two-phase process:
1. An *analysis phase* constructs the Control-Flow Graph (CFG) which
approximates the set of legitimate control-flow transfers
2. The CFG is used at runtime by an *enforcement component* to ensure that all
executed branches correspond to edges in the CFG

~~~
      <Control Flow Graph>

           func1()
           /    \
          /      \
         v        v             - function call 2 from 1 is allowed
      func2()   func3()         - function call 4 from 3 is forbidden
         |
         |
         V
      func4()
~~~

However, it is hard to construct fine grained CFG because of indirect branches
that are not determined at static analysis so there are approximation in most
CFG. In case of RAP, it implements type-based approximated CFG.

@sidebar(PAX RAP)
## PaX Reuse Attack Protector (RAP)

RAP is a defense mechanism against code reuse attack. It is a CFI technology
developed by PaX. RAP is included in grsecurity patch for linux kernel security,
but only the commercial version provides its full functionalities.<br>
RAP is implemented as a GCC compiler plugin, and it consists of two components:
1. A deterministic defense limiting function call and return location
2. A probabilistic defense to help ensure that a function can return to the
location where the function was called

### Indirect Control Transfer Protection

RAP implements CFI based on type-based indirect control flow graph (ICFG). It is
based on the idea that the ICFG **vertex categorization** can have the ICFG
approximation emerge automatically. It means that the analysis can be conducted
in function level without knowledge of the entire program.<br>
It categorizes functions by type: return type, function name and function
parameters. The type information extracted from each function and function
pointer is used to verify matching between function and function pointer
dereference (indirect call, function return, etc). Type matching uses hash
value calculated from appropriate type part of each function.<br>

A different set of type parts can be used for type hash by the sort of function.

| Usable parts in type hash | Return | Name | ’this’ | Parameters |
|---|:-:|:-:|:-:|:-:|
| non-class or static member function/ptr | Y | N | N/A | Y |
| non-virtual method/ptr | Y | N | N | Y |
| virtual method/ptr | N | N | N | Y |
| ancestor method/virtual method call | Y | Y | Y | Y |

Table: (RAP: RIP ROP) Type Hash Parts

Plugin code for function pointer protection:
~~~{.c}
// @rap_plugin/rap_fptr_pass.c
static unsigned int rap_fptr_execute(void)
{
  ...
  // ... through a function pointer
  fntype = TREE_TYPE(fntype);
  gcc_assert(TREE_CODE(fntype) == FUNCTION_TYPE || TREE_CODE(fntype) ==
   METHOD_TYPE);

  if (enable_type_call) {
    rap_instrument_fptr(&gsi);
    bb = gsi_bb(gsi);
    gcc_assert(call_stmt == gsi_stmt(gsi));
  }

  if (enable_type_ret) {
    hash = rap_hash_function_type(fntype, imprecise_rap_hash_flags);
    computed_hash = build_int_cst_type(rap_hash_type_node, -hash.hash);
    rap_mark_retloc(&gsi, computed_hash);
  }
}

...

// check the function hash of the target of the fptr
static void rap_instrument_fptr(gimple_stmt_iterator *gsi)
{
  ...
  if (TREE_CODE(fntype) == FUNCTION_TYPE) {
    computed_hash = build_rap_hash(call_stmt, fntype);
  } else {
    debug_tree(fntype);
    gcc_unreachable();
  }
  ...
  target_hash = get_rap_hash(&stmts, loc, fptr, -rap_hash_offset);
  gsi_insert_seq_before(gsi, stmts, GSI_SAME_STMT);

  // compare target_hash against computed function hash
  // bail out on mismatch
  check_hash = gimple_build_cond(NE_EXPR, target_hash, computed_hash, NULL_TREE,
    NULL_TREE);
  gimple_set_location(check_hash, loc);
  gsi_insert_before(gsi, check_hash, GSI_NEW_STMT);
  ...
~~~

Plugin code for return location protection:
~~~{.c}
// @rap_plugin/rap_ret_pass.c
/*
 * insert the equivalent of
 * if (*(long *)((void *)retaddr+N) != (long)-function_hash) abort();
 */
static void check_retaddr(gimple_stmt_iterator *gsi, tree new_retaddr)
{
  ...
#ifdef TARGET_386
	if (TARGET_64BIT)
		target_hash = get_rap_hash(&stmts, loc, new_retaddr, -16);
	else
		target_hash = get_rap_hash(&stmts, loc, new_retaddr, -10);
#else
  ...
  hash = rap_hash_function_type(TREE_TYPE(current_function_decl),
    imprecise_rap_hash_flags);
  computed_hash = build_int_cst_type(rap_hash_type_node, -hash.hash);

  stmt = gimple_build_cond(NE_EXPR, target_hash, computed_hash, NULL_TREE,
    NULL_TREE);
  gimple_set_location(stmt, loc);
  gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);
  ...
~~~

### Return Address Protection

Return Address Protection is an another defense mechanism of RAP. It is
conceptually based on the XOR canary approach. RAP encrypts the return address
with a key which is stored in a reserved register (**r12** on amd64). This key is
highly resistant to leaking as it shouldn't be stored or spilled into memory.
In addition to this, grsecurity says *RAP cookie* (the encryption key) does not
stay, but changes per task, system call, and iteration in some infinite loops.

Following is an example for RAP: Return Address Protection. Its full
implementation is not revealed at PaX test patch.
~~~{.c}
// RAP example
push %rbx
mov 8(%rsp),%rbx
xor %r12,%rbx
...
xor %r12,%rbx
cmp %rbx,8(%rsp)
jnz .error
pop %rbx
retn
.error:
ud2
~~~

### References
- [Control-Flow Integrity: Precision, Security, andPerformance](https://nebelwelt.net/publications/files/17CSUR.pdf)
- [ROP is Still Dangerous: Breaking Modern Defenses](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-carlini.pdf)
- [On the Effectiveness of Type-based Control Flow Integrity (TROP)](https://arxiv.org/pdf/1810.10649)
- [RAP: RIP ROP](https://pax.grsecurity.net/docs/PaXTeam-H2HC15-RAP-RIP-ROP.pdf)
- [PAX RAP FAQ](https://grsecurity.net/rap_faq.php)
- [PAX linux patch: test version](https://github.com/linux-scraping/pax-patches/raw/master/pax-4.9/pax-linux-4.9.24-test7.patch)

@sidebar(MTE)
## ARM's Memory Tagging Extensions (MTE)

XXX. write here

### References
- [MTE White Paper](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Arm_Memory_Tagging_Extension_Whitepaper.pdf?revision=ef3521b9-322c-4536-a800-5ee35a0e7665&la=en)
- [MTE Patch](https://lkml.org/lkml/2019/7/25/725)
