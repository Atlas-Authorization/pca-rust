//! Core-module WebAssembly host (feature `sandbox-wasm`): the tool is a core module whose only import is
//! `pca:act.{invoke,handle_count,handle_verb}`, so it has no filesystem, network, clock, random or environment access (no WASI is
//! linked). Limits, none optional: an instruction budget (fuel, required), a wall-clock deadline (epoch interruption), a hard
//! linear-memory cap, one declared-maximum non-shared 32-bit memory, and the import allow-list. Anything the engine cannot enforce
//! refuses to run. Reasons are the reference's: module_size, malformed_module, memory_limits, ambient_import:<m>.<n>, no_entry,
//! trap:RuntimeError, trap:LinkError, plus bad_fuel, fuel_exhausted, timeout.
use crate::sandbox_handles::{HandleTable, ALLOWED_IMPORTS, IMPORT_MODULE, USE_ERR};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, Module, ResourceLimiter, Store, Trap, Val,
};

pub type RunResult = Result<i64, String>;

#[derive(Clone)]
pub struct CoreOptions {
    pub fuel: u64,
    pub timeout_ms: u64,
    pub max_module_bytes: usize,
    /// Largest linear memory a tool may declare, in 64 KiB pages (default 256 = 16 MiB).
    pub max_memory_pages: u64,
    pub max_result_bytes: usize,
}

impl CoreOptions {
    /// `fuel` has no default: a budget is a decision.
    pub fn new(fuel: u64) -> CoreOptions {
        CoreOptions {
            fuel,
            timeout_ms: 5000,
            max_module_bytes: 1 << 20,
            max_memory_pages: 256,
            max_result_bytes: 1 << 20,
        }
    }
}

struct Ctx {
    table: Arc<Mutex<HandleTable>>,
    max_bytes: usize,
    max_result: usize,
    refused: bool,
}

impl ResourceLimiter for Ctx {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // like the reference (a JS WebAssembly.Memory): a grow past the cap or the declared maximum is a quiet -1, not a trap.
        // The static checks (declared maximum within the cap) refuse everything else before a single instruction runs.
        Ok(maximum.is_some() && desired <= self.max_bytes)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 100_000)
    }
}

type MemLimits = (u64, u64, Option<u64>, bool);

/// Parse only the memory section (so a non-exported memory is seen too): Err = unparseable, Ok(None) = no memory, else
/// (count, min, max, shared). A flag above 3 (memory64 and newer) reports as shared, which is refused.
fn memory_limits(b: &[u8]) -> Result<Option<MemLimits>, ()> {
    if b.len() < 8 || b[0] != 0 || b[1] != 0x61 || b[2] != 0x73 || b[3] != 0x6d {
        return Err(());
    }
    fn leb(b: &[u8], o: &mut usize) -> Result<u64, ()> {
        let mut r: u64 = 0;
        for shift in (0..35).step_by(7) {
            let x = *b.get(*o).ok_or(())?;
            *o += 1;
            r += ((x & 0x7f) as u64) << shift;
            if x & 0x80 == 0 {
                return Ok(r);
            }
        }
        Err(())
    }
    let mut o = 8usize;
    while o < b.len() {
        let id = b[o];
        o += 1;
        let size = leb(b, &mut o)? as usize;
        let end = o.checked_add(size).ok_or(())?;
        if end > b.len() {
            return Err(());
        }
        if id == 5 {
            let count = leb(b, &mut o)?;
            if count == 0 {
                return Ok(None);
            }
            let flag = *b.get(o).ok_or(())?;
            o += 1;
            if flag > 3 {
                return Ok(Some((count, u64::MAX, None, true)));
            }
            let min = leb(b, &mut o)?;
            let max = if flag & 1 != 0 {
                Some(leb(b, &mut o)?)
            } else {
                None
            };
            return Ok(Some((count, min, max, flag & 2 != 0)));
        }
        o = end;
    }
    Ok(None)
}

/// The guest's window [ptr, ptr+len) as unsigned 32-bit values; None when it is outside linear memory.
fn window(c: &mut Caller<'_, Ctx>, ptr: i32, len: i32) -> Option<(wasmtime::Memory, usize, usize)> {
    let mem = c.get_export("memory")?.into_memory()?;
    let (p, l) = (ptr as u32 as usize, len as u32 as usize);
    (p.checked_add(l)? <= mem.data_size(&*c)).then_some((mem, p, l))
}

fn code(reason: &str) -> i32 {
    USE_ERR
        .iter()
        .find(|(k, _)| *k == reason)
        .map(|(_, c)| *c)
        .unwrap_or(-5)
}

fn classify(e: &wasmtime::Error, refused: bool, instantiating: bool) -> String {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => "fuel_exhausted".into(),
        Some(Trap::Interrupt) => "timeout".into(),
        _ if refused => "memory_limits".into(),
        None if instantiating => "trap:LinkError".into(),
        _ => "trap:RuntimeError".into(),
    }
}

/// Run `bytes` (a core module) and call its export `entry` over `table`. The table is locked only during a handle call.
pub fn run(
    table: &Arc<Mutex<HandleTable>>,
    bytes: &[u8],
    entry: &str,
    o: &CoreOptions,
) -> RunResult {
    if o.fuel < 1 {
        return Err("bad_fuel".into());
    }
    if o.max_memory_pages < 1 || o.timeout_ms < 1 {
        return Err("bad_limits".into());
    }
    if bytes.is_empty() || bytes.len() > o.max_module_bytes {
        return Err("module_size".into());
    }
    match memory_limits(bytes) {
        Err(()) => return Err("malformed_module".into()),
        Ok(Some((count, min, max, shared)))
            if count > 1
                || shared
                || max.is_none()
                || min > o.max_memory_pages
                || max.unwrap_or(u64::MAX) > o.max_memory_pages =>
        {
            return Err("memory_limits".into())
        }
        Ok(_) => {}
    }
    let mut cfg = Config::new();
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    cfg.wasm_multi_memory(false);
    cfg.wasm_memory64(false);
    // threads and the component model are wasmtime Cargo features that are not enabled: those proposals are compiled out.
    let engine = Engine::new(&cfg).map_err(|_| "limit_unenforceable:fuel".to_string())?;
    let module = Module::new(&engine, bytes).map_err(|_| "malformed_module".to_string())?;
    for i in module.imports() {
        if i.module() != IMPORT_MODULE
            || !matches!(i.ty(), ExternType::Func(_))
            || !ALLOWED_IMPORTS.contains(&i.name())
        {
            return Err(format!("ambient_import:{}.{}", i.module(), i.name()));
        }
    }
    let mut linker: Linker<Ctx> = Linker::new(&engine);
    linker
        .func_wrap(IMPORT_MODULE, "handle_count", |c: Caller<'_, Ctx>| -> i32 {
            c.data().table.lock().map(|t| t.size() as i32).unwrap_or(0)
        })
        .and_then(|l| {
            l.func_wrap(
                IMPORT_MODULE,
                "handle_verb",
                |mut c: Caller<'_, Ctx>, h: i32, ptr: i32, cap: i32| -> i32 {
                    let verb = c.data().table.lock().ok().and_then(|t| t.verb_of(h as f64));
                    let Some(verb) = verb else {
                        return code("unknown_handle");
                    };
                    let Some((mem, p, l)) = window(&mut c, ptr, cap) else {
                        return code("bad_memory");
                    };
                    let enc = verb.as_bytes();
                    if enc.len() > l {
                        return code("out_too_small");
                    }
                    mem.data_mut(&mut c)[p..p + enc.len()].copy_from_slice(enc);
                    enc.len() as i32
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                IMPORT_MODULE,
                "invoke",
                |mut c: Caller<'_, Ctx>, h: i32, ptr: i32, cap: i32| -> i32 {
                    // validate the guest's output window before spending the use
                    let Some((mem, p, l)) = window(&mut c, ptr, cap) else {
                        return code("bad_memory");
                    };
                    let r = match c.data().table.lock() {
                        Ok(mut t) => t.use_handle(h as f64),
                        Err(_) => return code("executor_error"),
                    };
                    match r {
                        Err(reason) => code(reason),
                        Ok(b) if b.len() > c.data().max_result || b.len() > l => {
                            code("out_too_small")
                        }
                        Ok(b) => {
                            mem.data_mut(&mut c)[p..p + b.len()].copy_from_slice(&b);
                            b.len() as i32
                        }
                    }
                },
            )
        })
        .map_err(|_| "limit_unenforceable:linker".to_string())?;
    let ctx = Ctx {
        table: table.clone(),
        max_bytes: (o.max_memory_pages as usize) * 65536,
        max_result: o.max_result_bytes,
        refused: false,
    };
    let mut store = Store::new(&engine, ctx);
    store.limiter(|c| c);
    store
        .set_fuel(o.fuel)
        .map_err(|_| "limit_unenforceable:fuel".to_string())?;
    store.set_epoch_deadline(1);
    // the ticker ends as soon as the run does (the sender is dropped)
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let ticker = engine.clone();
    let ms = o.timeout_ms;
    std::thread::spawn(move || {
        if done_rx.recv_timeout(Duration::from_millis(ms)).is_err() {
            ticker.increment_epoch();
        }
    });
    let out = (|| -> RunResult {
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| classify(&e, store.data().refused, true))?;
        let f = instance.get_func(&mut store, entry).ok_or("no_entry")?;
        let ty = f.ty(&store);
        if ty.params().len() != 0 {
            return Err("no_entry".into());
        }
        let mut results = vec![Val::I32(0); ty.results().len()];
        f.call(&mut store, &[], &mut results)
            .map_err(|e| classify(&e, store.data().refused, false))?;
        Ok(match results.first() {
            Some(Val::I32(v)) => *v as i64,
            _ => 0,
        })
    })();
    drop(done_tx);
    out
}
