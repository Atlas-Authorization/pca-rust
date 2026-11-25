//! circom witness calculator: runs the `.wasm` produced by `circom --wasm` on the pure-Rust wasmi interpreter, speaking the
//! same protocol as circom's generated `witness_calculator.js` (version 2: FNV-1a signal hashes, a shared read/write memory of
//! 32-bit limbs, `exceptionHandler` for failures).
use num_bigint::{BigInt, BigUint};
use serde_json::Value;
use wasmi::{Caller, Engine, Linker, Module, Store};

struct St {
    err: Option<i32>,
}

fn e<T: std::fmt::Display>(x: T) -> String {
    x.to_string()
}

/// FNV-1a over the signal name, split into the two 32-bit halves the wasm expects.
fn fnv(name: &str) -> (i32, i32) {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    ((h >> 32) as u32 as i32, h as u32 as i32)
}

fn flat(v: &Value, out: &mut Vec<BigInt>) -> Result<(), String> {
    match v {
        Value::Array(a) => a.iter().try_for_each(|x| flat(x, out)),
        Value::String(s) => {
            let (neg, t) = s.strip_prefix('-').map_or((false, s.as_str()), |t| (true, t));
            let n = match t.strip_prefix("0x") {
                Some(h) => BigUint::parse_bytes(h.as_bytes(), 16),
                None => BigUint::parse_bytes(t.as_bytes(), 10),
            }
            .ok_or_else(|| format!("input value {s:?} is not an integer"))?;
            out.push(if neg { -BigInt::from(n) } else { BigInt::from(n) });
            Ok(())
        }
        Value::Number(n) => {
            let i = n.as_i64().ok_or_else(|| format!("input value {n} is not an integer"))?;
            out.push(BigInt::from(i));
            Ok(())
        }
        other => Err(format!("input value {other} is not a number, string or array")),
    }
}

/// Runs the witness calculator over `input` (a JSON object of signal name to value / nested array) and returns every witness
/// entry, index 0 first (the constant 1), as 32 little-endian bytes each. `modulus` is the scalar field the circuit was compiled for.
pub fn calculate(wasm: &[u8], input: &Value, modulus: &BigUint) -> Result<Vec<[u8; 32]>, String> {
    let Some(obj) = input.as_object() else {
        return Err("input must be a JSON object".into());
    };
    let engine = Engine::default();
    let module = Module::new(&engine, wasm).map_err(e)?;
    let mut store = Store::new(&engine, St { err: None });
    let mut l = <Linker<St>>::new(&engine);
    l.func_wrap("runtime", "exceptionHandler", |mut c: Caller<'_, St>, code: i32| {
        c.data_mut().err = Some(code);
    })
    .map_err(e)?;
    // The messages are read after the call (the wasm keeps the last one); the older circom 2.0.x imports are accepted and ignored.
    l.func_wrap("runtime", "printErrorMessage", || {}).map_err(e)?;
    l.func_wrap("runtime", "writeBufferMessage", || {}).map_err(e)?;
    l.func_wrap("runtime", "showSharedRWMemory", || {}).map_err(e)?;
    l.func_wrap("runtime", "error", |_: i32, _: i32, _: i32, _: i32, _: i32, _: i32| {})
        .map_err(e)?;
    l.func_wrap("runtime", "log", |_: i32| {}).map_err(e)?;
    l.func_wrap("runtime", "logSetSignal", |_: i32, _: i32| {}).map_err(e)?;
    l.func_wrap("runtime", "logGetSignal", |_: i32, _: i32| {}).map_err(e)?;
    l.func_wrap("runtime", "logFinishComponent", |_: i32| {}).map_err(e)?;
    l.func_wrap("runtime", "logStartComponent", |_: i32| {}).map_err(e)?;
    let inst = l.instantiate(&mut store, &module).map_err(e)?.start(&mut store).map_err(e)?;

    macro_rules! f {
        ($n:literal, $p:ty, $r:ty) => {
            inst.get_typed_func::<$p, $r>(&store, $n)
                .map_err(|x| format!("witness wasm lacks {}: {x}", $n))?
        };
    }
    let get_version = f!("getVersion", (), i32);
    let init = f!("init", i32, ());
    let get_input_size = f!("getInputSize", (), i32);
    let get_input_signal_size = f!("getInputSignalSize", (i32, i32), i32);
    let set_input_signal = f!("setInputSignal", (i32, i32, i32), ());
    let write_shared = f!("writeSharedRWMemory", (i32, i32), ());
    let read_shared = f!("readSharedRWMemory", i32, i32);
    let get_witness_size = f!("getWitnessSize", (), i32);
    let get_witness = f!("getWitness", i32, ());
    let get_message_char = f!("getMessageChar", (), i32);

    // Every wasm call goes through this: a failure is the recorded exception (with the wasm's own message) or the trap.
    macro_rules! call {
        ($t:expr, $($a:expr),*) => {{
            let r = $t.call(&mut store, ($($a),*));
            if let Some(code) = store.data().err {
                let mut msg = String::new();
                for _ in 0..4096 {
                    match get_message_char.call(&mut store, ()) {
                        Ok(0) | Err(_) => break,
                        Ok(c) => msg.push(char::from_u32(c as u32).unwrap_or('?')),
                    }
                }
                return Err(format!("witness calculation failed (code {code}) {}", msg.trim()));
            }
            r.map_err(e)?
        }};
    }

    if call!(get_version,) != 2 {
        return Err("unsupported circom witness calculator version (need 2)".into());
    }
    call!(init, 0);
    // A circom scalar is 8 little-endian 32-bit limbs on both supported curves (BN254 r and BLS12-381 r are at most 255 bits).
    let n32 = 8usize;
    let mut set = 0i32;
    for (name, v) in obj {
        let (hm, hl) = fnv(name);
        let mut vals = Vec::new();
        flat(v, &mut vals)?;
        let size = call!(get_input_signal_size, hm, hl);
        if size < 0 {
            return Err(format!("signal {name} is not an input of the circuit"));
        }
        if vals.len() != size as usize {
            return Err(format!("input signal {name}: expected {size} values, got {}", vals.len()));
        }
        for (i, x) in vals.iter().enumerate() {
            let m = BigInt::from(modulus.clone());
            let norm = ((x % &m) + &m) % &m;
            let bytes = norm.to_biguint().expect("non-negative").to_bytes_le();
            for j in 0..n32 {
                let mut w = [0u8; 4];
                for (k, b) in w.iter_mut().enumerate() {
                    *b = bytes.get(4 * j + k).copied().unwrap_or(0);
                }
                call!(write_shared, j as i32, u32::from_le_bytes(w) as i32);
            }
            call!(set_input_signal, hm, hl, i as i32);
            set += 1;
        }
    }
    let want = call!(get_input_size,);
    if set < want {
        return Err(format!("not all inputs have been set: {set} of {want}"));
    }
    let size = call!(get_witness_size,);
    let mut out = Vec::with_capacity(size.max(0) as usize);
    for i in 0..size {
        call!(get_witness, i);
        let mut b = [0u8; 32];
        for j in 0..n32 {
            let limb = call!(read_shared, j as i32) as u32;
            b[4 * j..4 * j + 4].copy_from_slice(&limb.to_le_bytes());
        }
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::fnv;

    #[test]
    fn fnv_known_answer() {
        // FNV-1a 64 of "a" is af63dc4c8601ec8c.
        assert_eq!(fnv("a"), (0xaf63_dc4cu32 as i32, 0x8601_ec8cu32 as i32));
    }
}
