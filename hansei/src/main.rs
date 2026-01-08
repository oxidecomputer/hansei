use anyhow::{Context as _, Result};
use clap::Parser;
use durin::TypeKind;
use durin::read::{CtfMember, CtfReader, CtfStruct, CtfType, TypeInfo, TypeReader};
use proc::Core;

use std::collections::HashMap;
use std::fs::{self};
use std::io::{self, Write};
use std::mem;
use std::num::NonZeroU64;
use std::ops::Range;
use std::path::PathBuf;

#[derive(clap::Parser)]
struct Args {
    /// The core dump to open.
    core: PathBuf,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,
}

fn main() {
    let args = Args::parse();
    let mut stdout = io::stdout().lock();

    if let Err(e) = exec(args, &mut stdout) {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "{e:#}");
        std::process::exit(1);
    }
}

fn exec(args: Args, _out: &mut dyn io::Write) -> Result<()> {
    let core = Core::open(&args.core)
        .with_context(|| format!("failed to open {} as a core", args.core.display()))?;
    let status = core.status();
    let brk_range = status.brk_range;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes)?;

    let mut type_map = HashMap::new();
    for ty in ctf.types() {
        let type_name = ty.name(&ctf);
        type_map.insert(type_name, ty);
    }

    let ctx_ty = type_map.get("tokio::runtime::context::Context").unwrap();
    let lwps = core.lwps()?;
    for lwp in &lwps {
        if let Some(addr) = find_context(lwp.tid, &brk_range, &core)? {
            eprintln!("Context for TID {}: {addr:#x}", lwp.tid);
            let x = ThreadCtx::read_from_core(&core, addr, ctx_ty, &ctf)?;
            eprintln!(
                "ThreadCtx {{\n  current_task: {:?}\n  budget: {:?}\n}}",
                x.current_task, x.budget
            );
        }
    }

    let ctx_ty = type_map.get("tokio::runtime::context::Context").unwrap();

    eprintln!("Context size: {}", ctx_ty.size(&ctf));
    for member in ctx_ty.members() {
        eprintln!(
            "MEMBER: {} - {}@{}",
            member.name(&ctf),
            member.ty(&ctf).name(&ctf),
            member.offset_bits / 8
        );
    }

    Ok(())
}

/// Find the address of the thread-local `tokio::runtime::context::Context` for
/// this LWP, if present. The first three u64s of this type form a
/// recognizeable pattern unlikely to be replicated by other types.
fn find_context(tid: u32, brk_range: &Range<u64>, core: &Core) -> Result<Option<u64>> {
    // So far I've always observed the Context at `tls[4]`, but there's no
    // reason to assume this will remain the case. Check all of the slots to be
    // safe.
    let tls = core.lwp_tsd(tid)?;
    for addr in tls {
        // The `tokio::runtime::context::Context` is heap allocated.
        if !brk_range.contains(&addr) {
            continue;
        }
        const CONTEXT_SIZE: u64 = 3 * size_of::<u64>() as u64;
        let mut buf = [0u8; CONTEXT_SIZE as usize];

        // The value may be unmapped.
        if core.pread_exact(&mut buf, addr).is_err() {
            continue;
        }
        let buf: [u64; 3] = unsafe { mem::transmute(buf) };

        // The first item is a refcell's `BorrowCounter` isize. In well-behaved
        // code this is always -1, 0, or 1. Values outside of this will trigger
        // a panic.
        let borrow_counter = buf[0] as i64;
        if !(-1..=1).contains(&borrow_counter) {
            continue;
        }

        // The next is the discriminant for the
        // Option<tokio::runtime::scheduler::Handle>. This may be 0, 1, or 2, as
        // CurrentThread, MultiThread, and None, respectively. We only care
        // about MultiThread.
        let discrim = buf[1];
        if discrim != 1 {
            continue;
        }

        // The third item is the pointer to the
        // tokio::runtime::scheduler::Handle, which is heap allocated.
        let handle = buf[2];
        if !brk_range.contains(&handle) {
            continue;
        }

        return Ok(Some(addr));
    }

    Ok(None)
}

trait ReadFromCore: Sized {
    fn read_from_core(core: &Core, addr: u64, ty: &CtfType, ctf: &CtfReader) -> Result<Self>;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ThreadCtx {
    scheduler_addr: u64,
    current_task: TaskId,
    budget: Budget,
}

impl ReadFromCore for ThreadCtx {
    fn read_from_core(core: &Core, addr: u64, ty: &CtfType, ctf: &CtfReader) -> Result<Self> {
        let members = ty.members();
        let sched_memb = members.iter().find(|m| m.name(ctf) == "current").unwrap();
        let sched = sched_memb.ty(ctf);
        let task_memb = members
            .iter()
            .find(|m| m.name(ctf) == "current_task_id")
            .unwrap();
        let task_addr = addr + (task_memb.offset_bits as u64 / 8);
        let current_task = TaskId::read_from_core(core, task_addr, task_memb.ty(ctf), ctf)?;

        let budget_memb = members.iter().find(|m| m.name(ctf) == "budget").unwrap();
        let budget_addr = addr + (budget_memb.offset_bits as u64 / 8);
        let budget = Budget::read_from_core(core, budget_addr, budget_memb.ty(ctf), ctf)?;

        Ok(Self {
            scheduler_addr: 0,
            current_task,
            budget,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct TaskId(pub Option<NonZeroU64>);

impl ReadFromCore for TaskId {
    fn read_from_core(core: &Core, addr: u64, ty: &CtfType, ctf: &CtfReader) -> Result<Self> {
        if ty.kind() != TypeKind::Struct {
            anyhow::bail!("unexpected type {ty:?} for TaskId");
        }

        let size = ty.size(ctf);
        // TODO use CTF to track down the actual location of the value.
        assert_eq!(size, 8);
        let mut buf = vec![0u8; size as usize];
        core.pread_exact(&mut buf, addr)?;

        let val = u64::from_ne_bytes(buf[..].try_into().unwrap());
        let inner = match val {
            0 => None,
            v => Some(NonZeroU64::new(v).unwrap()),
        };
        Ok(Self(inner))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Budget(pub Option<u8>);

impl Budget {
    pub fn has_remaining(&self) -> bool {
        self.0.map_or(true, |b| b > 0)
    }
}

impl ReadFromCore for Budget {
    fn read_from_core(core: &Core, addr: u64, ty: &CtfType, ctf: &CtfReader) -> Result<Self> {
        let reader = TypeReader {
            path: &[
                TypeInfo {
                    name: "value",
                    type_kind: TypeKind::Struct,
                },
                TypeInfo {
                    name: "value",
                    type_kind: TypeKind::Struct,
                },
            ],
            target_member: "__0",
        };
        let target_ty = reader.read_type(ty, ctf).unwrap();

        if !matches!(target_ty.kind(), TypeKind::Struct) {
            anyhow::bail!("unexpected type {ty:?} for Budget");
        }

        // Read in the full size of the member of the source struct.
        let mut buf = vec![0u8; ty.size(ctf) as usize];
        core.pread_exact(&mut buf, addr)?;

        // TODO use CTF to track down the actual location of the value.
        assert_eq!(target_ty.size(ctf), 2);

        // The discriminant and value are the first two bytes.
        let val = u16::from_ne_bytes(buf[..2].try_into().unwrap());
        let inner = match val.to_ne_bytes() {
            [0, _] => None,
            [1, v @ ..=u8::MAX] => Some(v as u8),
            [_, out_of_range] => {
                anyhow::bail!("budget value {out_of_range} too large for u8")
            }
        };
        Ok(Self(inner))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Scheduler {
    x: u32,
}
