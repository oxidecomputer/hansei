// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The CFI walk over an object built by hand: an ELF image carrying
//! nothing but the program headers, an `.eh_frame_hdr` and the
//! `.eh_frame` gimli writes from a frame table. What these pin is
//! which byte a frame is looked up by — a return address is looked up
//! one byte back, an interrupted instruction where it is — since the
//! wrong row silently pops a wrong caller, and the real cores the
//! Linux suite walks never stop a thread on a function's first byte.

use crate::testhelper::{FakeTarget, STACK, TEXT, names, symbol, target};
use crate::{Backtrace, ObjectInfo, Unwinder};
use gimli::write::{
    Address, CallFrameInstruction as I, CommonInformationEntry, EhFrame, EndianVec, Expression,
    FrameDescriptionEntry, FrameTable,
};
use gimli::{BaseAddresses, CieOrFde, LittleEndian, UnwindContext, UnwindSection, X86_64};
use proc::Regs;

/// The functions the object describes, all inside the text mapping.
/// `A` ends in a call to a function that never returns, so its last
/// byte is a call and the return address that call pushed is `B`'s
/// first byte. `C` is the stack's bottom. `H` is a leaf: a signal
/// handler, in the trampoline test. `T` is the trampoline; its FDE
/// starts one byte before its symbol, as glibc's does, so that a
/// return address at its first byte looks up inside it.
const A: u64 = TEXT + 0x800;
const B: u64 = TEXT + 0x820;
const C: u64 = TEXT + 0x840;
const H: u64 = TEXT + 0x860;
const T: u64 = TEXT + 0x900;
const LEN: u64 = 0x20;

fn encoding() -> gimli::Encoding {
    gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 1,
        address_size: 8,
    }
}

/// The x86-64 CIE: the CFA is `rsp + 8` on entry, with the return
/// address just below it.
fn cie(signal_trampoline: bool) -> CommonInformationEntry {
    let mut cie = CommonInformationEntry::new(encoding(), 1, -8, X86_64::RA);
    cie.add_instruction(I::Cfa(X86_64::RSP, 8));
    cie.add_instruction(I::Offset(X86_64::RA, -8));
    cie.signal_trampoline = signal_trampoline;
    cie
}

/// A function with a frame pointer: `push rbp; mov rbp, rsp` and no
/// epilogue rows, so its last row still describes the full frame.
fn framed(addr: u64) -> FrameDescriptionEntry {
    let mut fde = FrameDescriptionEntry::new(Address::Constant(addr), LEN as u32);
    fde.add_instruction(1, I::CfaOffset(16));
    fde.add_instruction(1, I::Offset(X86_64::RBP, -16));
    fde.add_instruction(4, I::CfaRegister(X86_64::RBP));
    fde
}

/// A function whose return address is undefined: the stack's bottom.
fn bottom(addr: u64) -> FrameDescriptionEntry {
    let mut fde = FrameDescriptionEntry::new(Address::Constant(addr), LEN as u32);
    fde.add_instruction(0, I::Undefined(X86_64::RA));
    fde
}

/// A leaf: the CIE's entry row throughout.
fn leaf(addr: u64) -> FrameDescriptionEntry {
    FrameDescriptionEntry::new(Address::Constant(addr), LEN as u32)
}

/// The signal trampoline, restoring registers from a ucontext at the
/// stack pointer the way glibc's `__restore_rt` does: the CFA is the
/// interrupted stack pointer, read from the ucontext; the return
/// address is saved in it; the frame pointer, for the sake of covering
/// the value form and a value result, is computed rather than loaded.
fn trampoline() -> FrameDescriptionEntry {
    let mut fde = FrameDescriptionEntry::new(Address::Constant(T - 1), LEN as u32 + 1);
    let mut cfa = Expression::new();
    cfa.op_breg(X86_64::RSP, 0x10);
    cfa.op_deref();
    fde.add_instruction(0, I::CfaExpression(cfa));
    let mut ra = Expression::new();
    ra.op_breg(X86_64::RSP, 0x18);
    fde.add_instruction(0, I::Expression(X86_64::RA, ra));
    let mut rbp = Expression::new();
    rbp.op_breg(X86_64::RSP, 0x100);
    rbp.op(gimli::DW_OP_stack_value);
    fde.add_instruction(0, I::ValExpression(X86_64::RBP, rbp));
    fde
}

fn frame_table() -> FrameTable {
    let mut table = FrameTable::default();
    let plain = table.add_cie(cie(false));
    let signal = table.add_cie(cie(true));
    table.add_fde(plain, framed(A));
    table.add_fde(plain, framed(B));
    table.add_fde(plain, bottom(C));
    table.add_fde(plain, leaf(H));
    table.add_fde(signal, trampoline());
    table
}

/// The ELF image of the object, linked and mapped at `base`: the
/// header, one text `PT_LOAD` covering the whole image, the unwind
/// segment, then the `.eh_frame_hdr` and the `.eh_frame`.
fn object(base: u64, table: &FrameTable) -> Vec<u8> {
    const PT_LOAD: u32 = 1;
    const PT_GNU_EH_FRAME: u32 = 0x6474e550;
    const EHDR: usize = 0x40;
    const PHDR: usize = 0x38;
    const HDR_OFF: usize = EHDR + 2 * PHDR;

    let mut eh = EhFrame(EndianVec::new(LittleEndian));
    table
        .write_eh_frame(&mut eh)
        .expect("gimli writes the frame table");
    let eh_bytes = eh.0.into_vec();

    // Where each FDE landed, for the header's search table: gimli
    // reports offsets only on the way back in.
    let section = gimli::EhFrame::new(&eh_bytes, LittleEndian);
    let bases = BaseAddresses::default().set_eh_frame(0);
    let mut entries = section.entries(&bases);
    let mut fdes = Vec::new();
    while let Some(entry) = entries.next().expect("the written .eh_frame parses") {
        if let CieOrFde::Fde(partial) = entry {
            let fde = partial
                .parse(gimli::EhFrame::cie_from_offset)
                .expect("the written FDE parses");
            fdes.push((fde.initial_address(), fde.offset()));
        }
    }
    fdes.sort_unstable();

    let hdr_len = 12 + 8 * fdes.len();
    let eh_off = (HDR_OFF + hdr_len).next_multiple_of(8);
    let mut b = vec![0u8; eh_off + eh_bytes.len()];
    let put16 = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |b: &mut [u8], at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());

    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // little-endian
    b[6] = 1; // EV_CURRENT
    put16(&mut b, 16, 3); // ET_DYN
    put16(&mut b, 18, 62); // EM_X86_64
    put32(&mut b, 20, 1);
    put64(&mut b, 32, EHDR as u64); // e_phoff
    put16(&mut b, 52, EHDR as u16);
    put16(&mut b, 54, PHDR as u16);
    put16(&mut b, 56, 2); // e_phnum

    let phdr = |b: &mut [u8], at: usize, p_type: u32, flags: u32, off: usize, size: usize| {
        put32(b, at, p_type);
        put32(b, at + 4, flags);
        put64(b, at + 8, off as u64);
        put64(b, at + 16, base + off as u64);
        put64(b, at + 24, base + off as u64);
        put64(b, at + 32, size as u64);
        put64(b, at + 40, size as u64);
        put64(b, at + 48, 8);
    };
    let len = b.len();
    phdr(&mut b, EHDR, PT_LOAD, 5, 0, len);
    phdr(&mut b, EHDR + PHDR, PT_GNU_EH_FRAME, 4, HDR_OFF, hdr_len);

    // .eh_frame_hdr: version 1; the .eh_frame pointer pc-relative
    // sdata4; the count udata4; the table data-relative sdata4 pairs.
    b[HDR_OFF..HDR_OFF + 4].copy_from_slice(&[1, 0x1b, 0x03, 0x3b]);
    put32(&mut b, HDR_OFF + 4, (eh_off - HDR_OFF - 4) as u32);
    put32(&mut b, HDR_OFF + 8, fdes.len() as u32);
    for (i, (addr, offset)) in fdes.iter().enumerate() {
        let at = HDR_OFF + 12 + 8 * i;
        put32(&mut b, at, (addr - base - HDR_OFF as u64) as u32);
        put32(&mut b, at + 4, (eh_off + offset - HDR_OFF) as u32);
    }
    b[eh_off..].copy_from_slice(&eh_bytes);
    b
}

fn with_symbols(stack_words: &[(u64, u64)]) -> FakeTarget {
    let mut t = target(stack_words);
    t.symbols = vec![
        symbol("fn_a", A, LEN),
        symbol("fn_b", B, LEN),
        symbol("fn_c", C, LEN),
        symbol("handler", H, LEN),
        symbol("restore_rt", T, LEN),
    ];
    t
}

fn walk(t: &FakeTarget, regs: &Regs) -> Backtrace {
    let bytes = object(TEXT, &frame_table());
    let object = ObjectInfo::parse(&bytes, TEXT..TEXT + 0x1000).expect("the object parses");
    let unwinder = Unwinder {
        target: t,
        objects: std::slice::from_ref(&object),
        mappings: &t.mappings,
        missing: &[],
    };
    unwinder.unwind_stack(regs, &mut UnwindContext::new(), 8)
}

const S: u64 = STACK + 0x100;
const R: u64 = STACK + 0x300;

/// A thread stopped on a function's first byte — a stack overflow
/// faulting in the `push` that opens nearly every function, a bad
/// pointer dereferenced by a leaf's first instruction — is looked up
/// where it is. The byte before is the end of the function that
/// precedes it, whose last row describes a full frame, and popping
/// through that row reads the caller from the wrong slot with no sign
/// anything went wrong.
#[test]
fn test_a_stop_at_a_functions_first_byte_pops_its_caller() {
    let regs = Regs {
        rip: B,
        rsp: S,
        rbp: R,
        ..Regs::default()
    };
    let t = with_symbols(&[
        (S, C + 0x10), // the return address the call to B pushed
        (R, STACK + 0x400),
        (R + 8, A + 0x10), // what A's last row would take for the caller
    ]);
    let bt = walk(&t, &regs);
    let pcs: Vec<u64> = bt.frames.iter().map(|f| f.pc).collect();
    assert_eq!(pcs, [B, C + 0x10], "{:#?}", bt.frames);
    assert_eq!(names(&bt), ["fn_b", "fn_c"]);
    assert!(bt.frames[0].interrupted && !bt.frames[1].interrupted);
    // The entry row: the caller's rsp is just above the return
    // address, and its rbp is untouched.
    assert_eq!(bt.frames[1].regs.rsp, S + 8);
    assert_eq!(bt.frames[1].regs.rbp, R);
    assert_eq!(bt.truncated, None);
}

/// A return address that is the first byte of the next function — the
/// call that pushed it ended its caller — is looked up one byte back,
/// in the caller: that row pops the caller's caller, and the frame is
/// named for the caller. Looked up where it points, the frame would
/// take the next function's name and its entry row, which reads a
/// caller from a slot that holds no such thing.
#[test]
fn test_a_return_address_at_the_next_function_belongs_to_the_caller() {
    let regs = Regs {
        rip: H + 4,
        rsp: S,
        rbp: R,
        ..Regs::default()
    };
    let t = with_symbols(&[
        (S, B),            // H's return address: A's tail call landed here
        (S + 8, A + 0x10), // what B's entry row would take for the caller
        (R, STACK + 0x400),
        (R + 8, C + 0x10),
    ]);
    let bt = walk(&t, &regs);
    let pcs: Vec<u64> = bt.frames.iter().map(|f| f.pc).collect();
    assert_eq!(pcs, [H + 4, B, C + 0x10], "{:#?}", bt.frames);
    assert_eq!(names(&bt), ["handler", "fn_a", "fn_c"]);
    assert_eq!(bt.frames[1].lookup_pc(), B - 1);
    assert_eq!(bt.frames[2].regs.rsp, R + 16);
    assert_eq!(bt.frames[2].regs.rbp, STACK + 0x400);
    assert_eq!(bt.truncated, None);
}

/// A signal trampoline's CFI restores what the kernel saved, through
/// expression rules the walk evaluates against the ucontext, and the
/// frame it restores is stopped at the interrupted instruction: looked
/// up where it is, so an interrupt on a function's first byte pops
/// that function's caller, and named for it. The trampoline itself is
/// named by its own pc too — the kernel resumes it, nothing called it
/// — while its CFI is found by the byte before, which its FDE covers.
#[test]
fn test_a_signal_trampoline_restores_the_interrupted_frame() {
    // The ucontext the trampoline reads sits at the stack pointer it
    // runs with, just above the return address into it.
    let u = S + 8;
    let s2 = STACK + 0x800;
    let regs = Regs {
        rip: H + 4,
        rsp: S,
        rbp: R,
        ..Regs::default()
    };
    let t = with_symbols(&[
        (S, T),                // the handler's return address: the trampoline
        (u + 0x10, s2),        // the interrupted rsp
        (u + 0x18, B),         // the interrupted rip: B's first byte
        (s2, C + 0x10),        // the return address B's caller pushed
        (u + 0x108, A + 0x10), // what A's last row would take for the caller
    ]);
    let bt = walk(&t, &regs);
    let pcs: Vec<u64> = bt.frames.iter().map(|f| f.pc).collect();
    assert_eq!(pcs, [H + 4, T, B, C + 0x10], "{:#?}", bt.frames);
    let interrupted: Vec<bool> = bt.frames.iter().map(|f| f.interrupted).collect();
    assert_eq!(interrupted, [true, true, true, false]);
    assert_eq!(names(&bt), ["handler", "restore_rt", "fn_b", "fn_c"]);
    assert_eq!(bt.frames[1].lookup_pc(), T);
    assert_eq!(bt.frames[2].regs.rsp, s2);
    assert_eq!(bt.frames[2].regs.rbp, u + 0x100);
    assert_eq!(bt.frames[3].regs.rsp, s2 + 8);
    assert_eq!(bt.truncated, None);
}
