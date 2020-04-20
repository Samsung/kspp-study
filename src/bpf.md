@sidebar(eBPF Security)
# Hardening Hostile Code in eBPF
@kconfig(CONFIG_BPF)
@kconfig(CONFIG_BPF_SYSCALL)
@kconfig(CONFIG_BPF_JIT)
@kconfig(CONFIG_BPF_JIT_ALWAYS_ON)

@sidebar(Constant Blinding)
## Constant blinding in JIT

The JIT-ed memory is a common target 
for an attacker 
to place an arbitrary gadget 
(e.g., `syscall` in userspace).
One popular technique 
is to encode a desirable sequence of instructions 
as part of immediate values,
as x86-like CISC architectures 
provide a way to encode long bytes
into one instruction.
Constant blinding, 
as also known as constant folding,
is a technique 
to break immediate values,
avoiding the use of attacker-chosen constants
in the executable region.
It's worth noting that
there are numerous other techniques
(e.g., controlling the constant offset of direct branches)
but most of well-known attacks 
in the user space 
might not be too effective 
in the kernel space
as BPF provides only a smaller region 
with a smaller set of instructions available.
The implementation of constant blinding
is straightforward; xor the chosen immediate value 
with a random constant and before using it,
xor with the mangled value again with the random constant.


~~~~{.c}
int bpf_jit_blind_insn(const struct bpf_insn *from,
                       const struct bpf_insn *aux,
                       struct bpf_insn *to_buff)
{
  u32 imm_rnd = get_random_int();

  switch (from->code) {
  case BPF_ALU | BPF_ADD | BPF_K:
  case BPF_ALU | BPF_SUB | BPF_K:
  case BPF_ALU | BPF_AND | BPF_K:
  case BPF_ALU | BPF_OR  | BPF_K:
  case BPF_ALU | BPF_XOR | BPF_K:
  case BPF_ALU | BPF_MUL | BPF_K:
  case BPF_ALU | BPF_MOV | BPF_K:
  case BPF_ALU | BPF_DIV | BPF_K:
  case BPF_ALU | BPF_MOD | BPF_K:
    // NB. no more attack controllable instructions inserted
    // in the jitted, executable space (e.g., jump in the middle
    // of the immediate value)
    //
    //    MOV _, 0xdeadbeef
    // => MOV AX, [imm_rnd ^ 0xdeadbeef]
    //    XOR AX, imm_rnd
    //    MOV _, AX
    *to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
    *to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
    *to++ = BPF_ALU32_REG(from->code, from->dst_reg, BPF_REG_AX);
    break;
  ...
  }
  ...
}
~~~~

@sidebar(Spectre)
## Preventing Spectre

For non-privileged BPF programs,
the JIT engine 
applies mitigation schemes
against microarchitectural side-channel attacks,
such as Spectre.

__Variant 1 (Bounds Check Bypass).__
To prevent a speculator from performing an out-of-bound array access, 
it restricts its uses of an index on arrays that are accessible by 
an unprivileged user. 
The Linux kernel places such an check for
both its BPF interpreter and JIT code.

~~~~{.c}
// NB. in JIT-ed code:
//   array[index] -> array[index & mask]
u32 array_map_gen_lookup(struct bpf_map *map, struct bpf_insn *insn_buf) {
 ...
  if (map->unpriv_array) {
    *insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 4);
    *insn++ = BPF_ALU32_IMM(BPF_AND, ret, array->index_mask);
  } else {
    *insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 3);
  }
...
}

// NB. in an fuction called from an eBPF program
static void *percpu_array_map_lookup_elem(struct bpf_map *map, void *key)
{
  struct bpf_array *array = container_of(map, struct bpf_array, map);
  u32 index = *(u32 *)key;

  if (unlikely(index >= array->map.max_entries))
    return NULL;

  // NB. even after a speculator reaches here, it won't access
  // beyond the region of array->pptrs
  return this_cpu_ptr(array->pptrs[index & array->index_mask]);
}
~~~~

Recently, more sophisticated mitigation to 
thwart generic gadgets for V1
is introduced, 
which simulates the behavior of a speculator 
and detects a potential out-of-bound memory access.
Please refer to [2] for in-depth explanation.

__Variant 2 (Branch Target Injection).__
For indirect jumps introduced during the jitting, 
BPF applies the Retpoline mitigation, 
like the Linux kernel code.
For example, when the `BPF_JMP` instruction is a tail call,
it invokes the same bpf program again,
which is commonly implemented with an indirect jump 
(jumping right after the prologue).
`RETPOLINE_RAX_BPF_JIT` is 
introduced to produce 
a retpoline-enabled jump gadget
that can replace an indirect call with `rax`.

~~~~{.c}
// do_jit() {
//   ...
//   case BPF_JMP | BPF_TAIL_CALL:
//     emit_bpf_tail_call(&prog);
//     break;
// }
void emit_bpf_tail_call(u8 **pprog) {
   ...
  /*
   * Wow we're ready to jump into next BPF program
   * rdi == ctx (1st arg)
   * rax == prog->bpf_func + prologue_size
   */
  RETPOLINE_RAX_BPF_JIT();
  ..
} 
  
#  define RETPOLINE_RAX_BPF_JIT()                       \
do {                                                    \
  EMIT1_off32(0xE8, 7);    /* callq do_rop */           \
  /* spec_trap: */                                      \
  EMIT2(0xF3, 0x90);       /* pause */                  \
  EMIT3(0x0F, 0xAE, 0xE8); /* lfence */                 \
  EMIT2(0xEB, 0xF9);       /* jmp spec_trap */          \
  /* do_rop: */                                         \
  EMIT4(0x48, 0x89, 0x04, 0x24); /* mov %rax,(%rsp) */  \
  EMIT1(0xC3);             /* retq */                   \
} while (0)
~~~~


__Variant 4 (Speculative Store Bypass).__
To prevent a speculative memory disambiguation
from performing an arbitrary kernel memory read,
BPF verifier detects the malicious patterns
to trigger the speculation
at the time of loading a BPF program,
and sanitize the patterns.

~~~~{.c}
// NB: Safe execution flow by sanitizing a pattern
// Detect a case of reusing stack slot, and sanitize it.
// (1) r8 = *(u64 *)(r7 +0)   // slow read
// (2) *(u64 *)(r10 -72) = 0  // instruction for sanitizing
//     - this store becomes fast due to no depency on (1)
// (3) *(u64 *)(r8 +0) = r3   // this store becomes slow due to r8
// ---- at this time, (2) is likely to be completed before (3),
// ---- so it can perfectly eliminate an arbitrary unsafe address.
// (4) r1 = *(u64 *)(r6 +0)   // loads from either sanitized or safe address
// (5) r2 = *(u8 *)(r1 +0)    // no leak happens

struct bpf_insn_aux_data {
  ....
  int sanitize_stack_off; /* stack slot to be cleared */
  ....
}

static int check_stack_write(struct bpf_verifier_env *env, ....
{
  ....
  for (i = 0; i < BPF_REG_SIZE; i++) {
    if (state->stack[spi].slot_type[i] == STACK_MISC &&
        !env->allow_ptr_leaks) {
        int *poff = &env->insn_aux_data[insn_idx].sanitize_stack_off;
        int soff = (-spi - 1) * BPF_REG_SIZE;
        ....
        ....
        // NB: examine a store instruction writing to a stack slot.
        //     record this offset for detecting reused stack slot. 
        *poff = soff;
    }
    state->stack[spi].slot_type[i] = STACK_SPILL;
  }
  ....
}

static int convert_ctx_accesses(struct bpf_verifier_env *env)
{
  ....
  // NB: Is it a reused stack slot?
  if (type == BPF_WRITE &&
    env->insn_aux_data[i + delta].sanitize_stack_off) {
    struct bpf_insn patch[] = {
      ....
      // NB: Sanitize it with 0.
      BPF_ST_MEM(BPF_DW, BPF_REG_FP,
        env->insn_aux_data[i + delta].sanitize_stack_off,
        0),
      ....
    };
  }
}
~~~~

### References
- [bpf: prevent out-of-bounds speculation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2157399cc9898260d6031c5bfe45fe137c1fbe7)
- [bpf: prevent out of bounds speculation on pointer arithmetic](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=979d63d50c0c0f7bc537bf821e056cc9fe5abd38)
- [bpf: Prevent memory disambiguation attack](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=af86ca4e3088fe5eacf2f7e58c01fa68ca067672)
- [Speculose: Analyzing the Security Implications of Speculative Execution in CPUs](https://arxiv.org/pdf/1801.04084.pdf)
- [A Systematic Evaluation of Transient Execution Attacks and Defenses](https://arxiv.org/pdf/1811.05441.pdf)
