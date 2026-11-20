//! A classic-BPF interpreter over the instructions the seccomp programs use, fed a
//! `seccomp_data`, for tests that check a filter's verdict without installing it.

/// One instruction of either program type (`libc`'s and `seccompiler`'s `sock_filter`).
pub(crate) trait Instruction {
    fn parts(&self) -> (u16, u8, u8, u32);
}

impl Instruction for libc::sock_filter {
    fn parts(&self) -> (u16, u8, u8, u32) {
        (self.code, self.jt, self.jf, self.k)
    }
}

impl Instruction for seccompiler::sock_filter {
    fn parts(&self) -> (u16, u8, u8, u32) {
        (self.code, self.jt, self.jf, self.k)
    }
}

const LD: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
const AND: u32 = libc::BPF_ALU | libc::BPF_AND | libc::BPF_K;
const JA: u32 = libc::BPF_JMP | libc::BPF_JA;
const JEQ: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
const JGT: u32 = libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K;
const JGE: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
const JSET: u32 = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
const RET: u32 = libc::BPF_RET | libc::BPF_K;

/// The action `prog` returns for syscall `nr` with `args`, under architecture `arch`.
pub(crate) fn eval<I: Instruction>(prog: &[I], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&nr.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (i, arg) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
    }
    let (mut acc, mut pc) = (0u32, 0usize);
    loop {
        let (code, jt, jf, k) = prog[pc].parts();
        pc += 1;
        match u32::from(code) {
            LD => {
                let at = k as usize;
                acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            }
            AND => acc &= k,
            JA => pc += k as usize,
            RET => return k,
            code @ (JEQ | JGT | JGE | JSET) => {
                let taken = match code {
                    JEQ => acc == k,
                    JGT => acc > k,
                    JGE => acc >= k,
                    _ => acc & k != 0,
                };
                pc += usize::from(if taken { jt } else { jf });
            }
            other => panic!("instruction {other:#x} is outside the interpreted subset"),
        }
    }
}

/// What the kernel answers with every program in `progs` installed: the most restrictive action.
pub(crate) fn most_restrictive(actions: impl IntoIterator<Item = u32>) -> u32 {
    actions
        .into_iter()
        .min_by_key(|v| (v & libc::SECCOMP_RET_ACTION_FULL) as i32)
        .expect("at least one program")
}
