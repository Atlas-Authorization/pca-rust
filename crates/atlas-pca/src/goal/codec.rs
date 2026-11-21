//! The token-tape form of the typed IR, mirroring `codec.ts` tag for tag. Values are JSON trees (a discriminant `k`); encoding is
//! STRICT: anything that is not exactly an IR value is refused (as the reference's throws), so a malformed value never reaches
//! the kernel as something that merely happens to parse. The decoders read the compiler's own output (and goal tapes).
use super::js::*;
use super::render::Tok;
use serde_json::{json, Map, Value};

const OPS: [&str; 8] = ["eq", "ne", "lt", "lte", "gt", "gte", "in", "nin"];
const AGGS: [&str; 4] = ["count", "sum", "max", "distinct"];

type R = Result<(), String>;
fn err<T>(m: String) -> Result<T, String> {
    Err(format!("pca-goal: {m}"))
}
fn bad<T>(what: &str, v: U) -> Result<T, String> {
    err(format!("unknown {what}: {}", v.map(crate::js_stringify).unwrap_or_else(|| "undefined".into())))
}
fn k(o: &mut Vec<Tok>, n: i64) {
    o.push(Tok::Kw(n));
}
fn i(o: &mut Vec<Tok>, x: U) -> R {
    match safe_int(x) {
        Some(n) => {
            o.push(Tok::I(n));
            Ok(())
        }
        None => err(format!("{} is not a safe integer", js_str(x))),
    }
}
fn s(o: &mut Vec<Tok>, x: U) -> R {
    match x {
        Some(Value::String(v)) => {
            o.push(Tok::S(v.clone()));
            Ok(())
        }
        _ => err("string expected".into()),
    }
}
fn list(o: &mut Vec<Tok>, xs: U, mut f: impl FnMut(&mut Vec<Tok>, U) -> R) -> R {
    match xs {
        Some(Value::Array(a)) => {
            o.push(Tok::I(a.len() as i64));
            for x in a {
                f(o, Some(x))?;
            }
            Ok(())
        }
        _ => err("array expected".into()),
    }
}
fn strs(o: &mut Vec<Tok>, xs: U) -> R {
    list(o, xs, s)
}
fn field<'a>(v: U<'a>, name: &str) -> Result<U<'a>, String> {
    jget(v, name)
}

fn unit(o: &mut Vec<Tok>, u: U) -> R {
    let kk = field(u, "k")?;
    if is_str(kk, "money") {
        k(o, 300);
        return s(o, field(u, "ccy")?);
    }
    for (n, name) in [(301, "count"), (302, "duration"), (303, "instant"), (304, "bytes"), (305, "ratio")] {
        if is_str(kk, name) {
            k(o, n);
            return Ok(());
        }
    }
    bad("unit", u)
}
fn quantity(o: &mut Vec<Tok>, q: U) -> R {
    unit(o, field(q, "u")?)?;
    i(o, field(q, "n")?)
}
fn ty(o: &mut Vec<Tok>, t: U) -> R {
    let kk = field(t, "k")?;
    if is_str(kk, "q") {
        k(o, 310);
        unit(o, field(t, "u")?)
    } else if is_str(kk, "s") {
        k(o, 311);
        Ok(())
    } else {
        bad("type", t)
    }
}
fn atom(o: &mut Vec<Tok>, a: U) -> R {
    let kk = field(a, "k")?;
    if is_str(kk, "q") {
        k(o, 320);
        quantity(o, field(a, "q")?)
    } else if is_str(kk, "s") {
        k(o, 321);
        s(o, field(a, "s")?)
    } else {
        bad("set member (sets hold quantities and strings only)", a)
    }
}
fn value(o: &mut Vec<Tok>, v: U) -> R {
    let kk = field(v, "k")?;
    if is_str(kk, "q") {
        k(o, 330);
        quantity(o, field(v, "q")?)
    } else if is_str(kk, "s") {
        k(o, 331);
        s(o, field(v, "s")?)
    } else if is_str(kk, "set") {
        k(o, 332);
        list(o, field(v, "items")?, atom)
    } else {
        bad("value", v)
    }
}
fn term(o: &mut Vec<Tok>, t: U) -> R {
    let kk = field(t, "k")?;
    if is_str(kk, "param") {
        k(o, 340);
        s(o, field(t, "path")?)?;
        ty(o, field(t, "ty")?)
    } else if is_str(kk, "lit") {
        k(o, 341);
        value(o, field(t, "v")?)
    } else if is_str(kk, "hist") {
        k(o, 342);
        s(o, field(t, "bid")?)?;
        unit(o, field(t, "u")?)
    } else {
        bad("term", t)
    }
}
fn op(o: &mut Vec<Tok>, x: U) -> R {
    match x {
        Some(Value::String(v)) if OPS.contains(&v.as_str()) => {
            k(o, 350 + OPS.iter().position(|n| *n == v.as_str()).unwrap() as i64);
            Ok(())
        }
        _ => bad("operator", x),
    }
}
fn cond(o: &mut Vec<Tok>, c: U) -> R {
    let kk = field(c, "k")?;
    if is_str(kk, "true") {
        k(o, 360);
        Ok(())
    } else if is_str(kk, "cmp") {
        k(o, 361);
        op(o, field(c, "op")?)?;
        term(o, field(c, "l")?)?;
        term(o, field(c, "r")?)
    } else if is_str(kk, "and") || is_str(kk, "or") {
        k(o, if is_str(kk, "and") { 362 } else { 363 });
        cond(o, field(c, "a")?)?;
        cond(o, field(c, "b")?)
    } else if is_str(kk, "not") {
        k(o, 364);
        cond(o, field(c, "c")?)
    } else {
        bad("condition", c)
    }
}
fn part(o: &mut Vec<Tok>, p: U) -> R {
    let kk = field(p, "k")?;
    if is_str(kk, "exact") {
        k(o, 375);
        s(o, field(p, "id")?)
    } else if is_str(kk, "oneof") {
        k(o, 376);
        strs(o, field(p, "ids")?)
    } else if is_str(kk, "related") {
        k(o, 377);
        s(o, field(p, "rel")?)?;
        s(o, field(p, "anchor")?)
    } else {
        bad("resource part", p)
    }
}
fn res(o: &mut Vec<Tok>, r: U) -> R {
    let kk = field(r, "k")?;
    if is_str(kk, "exact") {
        k(o, 370);
        s(o, field(r, "id")?)
    } else if is_str(kk, "oneof") {
        k(o, 371);
        strs(o, field(r, "ids")?)
    } else if is_str(kk, "related") {
        k(o, 372);
        s(o, field(r, "rel")?)?;
        s(o, field(r, "anchor")?)
    } else if is_str(kk, "any") {
        k(o, 373);
        s(o, field(r, "reason")?)
    } else if is_str(kk, "all_of") {
        k(o, 374);
        list(o, field(r, "parts")?, part)
    } else {
        bad("resource selector", r)
    }
}
fn grant(o: &mut Vec<Tok>, g: U) -> R {
    k(o, 380);
    s(o, field(g, "gid")?)?;
    s(o, field(g, "verb")?)?;
    res(o, field(g, "res")?)?;
    cond(o, field(g, "cond")?)
}
fn target(o: &mut Vec<Tok>, t: U) -> R {
    let kk = field(t, "k")?;
    if is_str(kk, "verb") {
        k(o, 390);
        s(o, field(t, "verb")?)
    } else if is_str(kk, "effect") {
        k(o, 391);
        s(o, field(t, "cls")?)
    } else {
        bad("prohibit target", t)
    }
}
fn prohibit(o: &mut Vec<Tok>, p: U) -> R {
    k(o, 392);
    s(o, field(p, "pid")?)?;
    target(o, field(p, "target")?)?;
    res(o, field(p, "res")?)?;
    cond(o, field(p, "cond")?)
}
fn sel(o: &mut Vec<Tok>, x: U) -> R {
    let kk = field(x, "k")?;
    if is_str(kk, "gids") {
        k(o, 410);
        strs(o, field(x, "gids")?)
    } else if is_str(kk, "effect") {
        k(o, 411);
        s(o, field(x, "cls")?)
    } else {
        bad("selection", x)
    }
}
fn window(o: &mut Vec<Tok>, w: U) -> R {
    let kk = field(w, "k")?;
    if is_str(kk, "task") {
        k(o, 420);
        Ok(())
    } else if is_str(kk, "sliding") {
        k(o, 421);
        i(o, field(w, "ms")?)
    } else if is_str(kk, "period") {
        k(o, 422);
        i(o, field(w, "ms")?)?;
        i(o, field(w, "t0")?)
    } else if is_str(kk, "lifetime") {
        k(o, 423);
        Ok(())
    } else {
        bad("window", w)
    }
}
fn scope(o: &mut Vec<Tok>, x: U) -> R {
    let kk = field(x, "k")?;
    if is_str(kk, "session") {
        k(o, 430);
        Ok(())
    } else if is_str(kk, "principal") {
        k(o, 431);
        Ok(())
    } else if is_str(kk, "org") {
        k(o, 432);
        Ok(())
    } else if is_str(kk, "fleet") {
        k(o, 433);
        strs(o, field(x, "agents")?)
    } else {
        bad("scope", x)
    }
}
fn on_exceed(o: &mut Vec<Tok>, x: U) -> R {
    if is_str(x, "deny") {
        k(o, 440);
        Ok(())
    } else if is_str(x, "escalate") {
        k(o, 441);
        Ok(())
    } else {
        bad("on_exceed", x)
    }
}
fn bcore(o: &mut Vec<Tok>, b: U) -> R {
    let agg = field(b, "agg")?;
    let idx = match agg {
        Some(Value::String(v)) => AGGS.iter().position(|n| *n == v.as_str()),
        _ => None,
    };
    let idx = match idx {
        Some(x) => x,
        None => return bad("aggregate", agg),
    };
    k(o, 450);
    k(o, 400 + idx as i64);
    term(o, field(b, "value")?)?;
    s(o, field(b, "key")?)?;
    window(o, field(b, "window")?)?;
    scope(o, field(b, "scope")?)?;
    quantity(o, field(b, "cap")?)?;
    on_exceed(o, field(b, "onExceed")?)
}
fn bound(o: &mut Vec<Tok>, b: U) -> R {
    k(o, 451);
    s(o, field(b, "bid")?)?;
    sel(o, field(b, "sel")?)?;
    bcore(o, b)
}
fn validity(o: &mut Vec<Tok>, v: U) -> R {
    k(o, 460);
    i(o, field(v, "notBefore")?)?;
    i(o, field(v, "notAfter")?)?;
    i(o, field(v, "maxIdle")?)
}
fn bool_tok(o: &mut Vec<Tok>, x: U) {
    o.push(Tok::I(truthy(x) as i64));
}
fn deleg(o: &mut Vec<Tok>, d: U) -> R {
    k(o, 461);
    i(o, field(d, "maxDepth")?)?;
    bool_tok(o, field(d, "narrowOnly")?);
    strs(o, field(d, "mayTouch")?)
}
fn hole(o: &mut Vec<Tok>, h: U) -> R {
    k(o, 470);
    s(o, field(h, "hid")?)?;
    s(o, field(h, "q")?)?;
    strs(o, field(h, "domain")?)?;
    strs(o, field(h, "affects")?)?;
    bool_tok(o, field(h, "global")?);
    Ok(())
}

/// The goal as a token tape (the card of `GoalRender.dfy`).
pub fn encode_goal(g: &Value) -> Result<Vec<Tok>, String> {
    let g = Some(g);
    let mut o = Vec::new();
    k(&mut o, 480);
    i(&mut o, field(g, "v")?)?;
    s(&mut o, field(g, "principal")?)?;
    s(&mut o, field(g, "ontDigest")?)?;
    s(&mut o, field(g, "nlDigest")?)?;
    strs(&mut o, field(g, "sources")?)?;
    list(&mut o, field(g, "grants")?, grant)?;
    list(&mut o, field(g, "prohibits")?, prohibit)?;
    list(&mut o, field(g, "bounds")?, bound)?;
    validity(&mut o, field(g, "validity")?)?;
    deleg(&mut o, field(g, "deleg")?)?;
    list(&mut o, field(g, "escalateOn")?, cond)?;
    strs(&mut o, field(g, "wildcardAck")?)?;
    list(&mut o, field(g, "holes")?, hole)?;
    Ok(o)
}
fn param_decl(o: &mut Vec<Tok>, p: U) -> R {
    k(o, 500);
    s(o, field(p, "path")?)?;
    ty(o, field(p, "ty")?)
}
fn verb_decl(o: &mut Vec<Tok>, v: U) -> R {
    k(o, 501);
    s(o, field(v, "verb")?)?;
    s(o, field(v, "cls")?)?;
    list(o, field(v, "params")?, param_decl)
}
fn rel_decl(o: &mut Vec<Tok>, r: U) -> R {
    k(o, 502);
    s(o, field(r, "rel")?)?;
    s(o, field(r, "anchor")?)?;
    strs(o, field(r, "members")?)
}
pub fn encode_ontology(x: &Value) -> Result<Vec<Tok>, String> {
    let x = Some(x);
    let mut o = Vec::new();
    k(&mut o, 510);
    list(&mut o, field(x, "verbs")?, verb_decl)?;
    list(&mut o, field(x, "rels")?, rel_decl)?;
    Ok(o)
}
/// Sorted (UTF-16 order) keys of a parameter map, each entry encoded with `f`.
fn keyed(o: &mut Vec<Tok>, m: U, mut f: impl FnMut(&mut Vec<Tok>, U) -> R, tag: i64) -> R {
    let mut keys = okeys(m)?;
    keys.sort_by(|a, b| u16cmp(a, b));
    o.push(Tok::I(keys.len() as i64));
    for key in &keys {
        k(o, tag);
        o.push(Tok::S(key.clone()));
        f(o, oget(m, key))?;
    }
    Ok(())
}
fn act(o: &mut Vec<Tok>, a: U) -> R {
    k(o, 530);
    s(o, field(a, "verb")?)?;
    s(o, field(a, "res")?)?;
    keyed(o, field(a, "params")?, value, 520)?;
    i(o, field(a, "t")?)?;
    s(o, field(a, "sess")?)?;
    s(o, field(a, "prin")?)?;
    s(o, field(a, "org")?)?;
    s(o, field(a, "agent")?)?;
    i(o, field(a, "depth")?)
}
pub fn encode_act(a: &Value) -> Result<Vec<Tok>, String> {
    let mut o = Vec::new();
    act(&mut o, Some(a))?;
    Ok(o)
}
fn adm(o: &mut Vec<Tok>, a: U) -> R {
    k(o, 531);
    s(o, field(a, "gid")?)?;
    act(o, field(a, "act")?)
}
pub fn encode_hist(h: &Value) -> Result<Vec<Tok>, String> {
    let h = Some(h);
    let mut o = Vec::new();
    k(&mut o, 541);
    list(&mut o, field(h, "adms")?, adm)?;
    i(&mut o, field(h, "last")?)?;
    keyed(&mut o, field(h, "aggs")?, quantity, 540)?;
    Ok(o)
}

// ---- tapes as JSON ([["k", n] | ["i", n] | ["s", text], ...])
pub fn tape_to_json(t: &[Tok]) -> Value {
    Value::Array(
        t.iter()
            .map(|x| match x {
                Tok::Kw(n) => json!(["k", n]),
                Tok::I(n) => json!(["i", n]),
                Tok::S(v) => json!(["s", v]),
            })
            .collect(),
    )
}
pub fn tape_from_json(v: &Value) -> Result<Vec<Tok>, String> {
    let a = v.as_array().ok_or("pca-goal: tape must be an array")?;
    a.iter()
        .map(|x| {
            let p = x.as_array().filter(|p| p.len() >= 2).ok_or("pca-goal: malformed token")?;
            match (p[0].as_str(), &p[1]) {
                (Some("k"), n) => any_int(n).map(Tok::Kw).ok_or_else(|| "pca-goal: keyword expected".to_string()),
                (Some("i"), n) => any_int(n).map(Tok::I).ok_or_else(|| "pca-goal: integer expected".to_string()),
                (Some("s"), Value::String(t)) => Ok(Tok::S(t.clone())),
                _ => Err("pca-goal: malformed token".to_string()),
            }
        })
        .collect()
}

// ---- decoding of the compiler's output and of goal tapes
pub struct TapeReader<'a> {
    t: &'a [Tok],
    p: usize,
}
type D<T> = Result<T, String>;
impl<'a> TapeReader<'a> {
    pub fn new(t: &'a [Tok]) -> Self {
        TapeReader { t, p: 0 }
    }
    fn next(&mut self) -> D<&'a Tok> {
        let x = self.t.get(self.p).ok_or_else(|| "pca-goal: truncated tape".to_string())?;
        self.p += 1;
        Ok(x)
    }
    fn k(&mut self) -> D<i64> {
        match self.next()? {
            Tok::Kw(n) => Ok(*n),
            _ => err("keyword expected".into()),
        }
    }
    fn int(&mut self) -> D<i64> {
        match self.next()? {
            Tok::I(n) => Ok(*n),
            _ => err("integer expected".into()),
        }
    }
    fn str(&mut self) -> D<String> {
        match self.next()? {
            Tok::S(v) => Ok(v.clone()),
            _ => err("string expected".into()),
        }
    }
    pub fn done(&self) -> bool {
        self.p >= self.t.len()
    }
    fn list<T>(&mut self, mut f: impl FnMut(&mut Self) -> D<T>) -> D<Vec<T>> {
        let n = self.int()?;
        if n < 0 {
            return err("negative length".into());
        }
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }
    fn strs(&mut self) -> D<Vec<String>> {
        self.list(|r| r.str())
    }
    fn expect(&mut self, n: i64, what: &str) -> D<()> {
        if self.k()? != n {
            return err(format!("{what} expected"));
        }
        Ok(())
    }
    fn unit(&mut self) -> D<Value> {
        let n = self.k()?;
        if n == 300 {
            return Ok(json!({"k": "money", "ccy": self.str()?}));
        }
        match n {
            301 => Ok(json!({"k": "count"})),
            302 => Ok(json!({"k": "duration"})),
            303 => Ok(json!({"k": "instant"})),
            304 => Ok(json!({"k": "bytes"})),
            305 => Ok(json!({"k": "ratio"})),
            _ => err(format!("bad unit tag {n}")),
        }
    }
    fn q(&mut self) -> D<Value> {
        let u = self.unit()?;
        Ok(json!({"u": u, "n": self.int()?}))
    }
    fn ty(&mut self) -> D<Value> {
        match self.k()? {
            310 => Ok(json!({"k": "q", "u": self.unit()?})),
            311 => Ok(json!({"k": "s"})),
            n => err(format!("bad type tag {n}")),
        }
    }
    fn atom(&mut self) -> D<Value> {
        match self.k()? {
            320 => Ok(json!({"k": "q", "q": self.q()?})),
            321 => Ok(json!({"k": "s", "s": self.str()?})),
            n => err(format!("bad atom tag {n}")),
        }
    }
    fn v(&mut self) -> D<Value> {
        match self.k()? {
            330 => Ok(json!({"k": "q", "q": self.q()?})),
            331 => Ok(json!({"k": "s", "s": self.str()?})),
            332 => Ok(json!({"k": "set", "items": self.list(|r| r.atom())?})),
            n => err(format!("bad value tag {n}")),
        }
    }
    fn term(&mut self) -> D<Value> {
        match self.k()? {
            340 => {
                let path = self.str()?;
                Ok(json!({"k": "param", "path": path, "ty": self.ty()?}))
            }
            341 => Ok(json!({"k": "lit", "v": self.v()?})),
            342 => {
                let bid = self.str()?;
                Ok(json!({"k": "hist", "bid": bid, "u": self.unit()?}))
            }
            n => err(format!("bad term tag {n}")),
        }
    }
    fn op(&mut self) -> D<&'static str> {
        let x = self.k()? - 350;
        if (0..8).contains(&x) {
            Ok(OPS[x as usize])
        } else {
            err("bad operator".into())
        }
    }
    fn nc(&mut self) -> D<Value> {
        match self.k()? {
            600 => Ok(json!({"k": "true"})),
            601 => Ok(json!({"k": "false"})),
            602 => {
                let op = self.op()?;
                let l = self.term()?;
                Ok(json!({"k": "atom", "op": op, "l": l, "r": self.term()?}))
            }
            603 => {
                let a = self.nc()?;
                Ok(json!({"k": "and", "a": a, "b": self.nc()?}))
            }
            604 => {
                let a = self.nc()?;
                Ok(json!({"k": "or", "a": a, "b": self.nc()?}))
            }
            n => err(format!("bad condition tag {n}")),
        }
    }
    fn res_pat(&mut self) -> D<Value> {
        match self.k()? {
            630 => Ok(json!({"k": "star"})),
            631 => Ok(json!({"k": "set", "ids": self.strs()?})),
            n => err(format!("bad resource pattern tag {n}")),
        }
    }
    fn window(&mut self) -> D<Value> {
        match self.k()? {
            420 => Ok(json!({"k": "task"})),
            421 => Ok(json!({"k": "sliding", "ms": self.int()?})),
            422 => {
                let ms = self.int()?;
                Ok(json!({"k": "period", "ms": ms, "t0": self.int()?}))
            }
            423 => Ok(json!({"k": "lifetime"})),
            n => err(format!("bad window tag {n}")),
        }
    }
    fn scope(&mut self) -> D<Value> {
        match self.k()? {
            430 => Ok(json!({"k": "session"})),
            431 => Ok(json!({"k": "principal"})),
            432 => Ok(json!({"k": "org"})),
            433 => Ok(json!({"k": "fleet", "agents": self.strs()?})),
            n => err(format!("bad scope tag {n}")),
        }
    }
    fn agg(&mut self) -> D<&'static str> {
        let x = self.k()? - 400;
        if (0..4).contains(&x) {
            Ok(AGGS[x as usize])
        } else {
            err("bad aggregate".into())
        }
    }
    fn on_exceed(&mut self) -> D<&'static str> {
        match self.k()? {
            440 => Ok("deny"),
            441 => Ok("escalate"),
            _ => err("bad on_exceed".into()),
        }
    }
    /// The bound's shared core as members of `m` (after the 450 tag was consumed).
    fn core_into(&mut self, m: &mut Map<String, Value>) -> D<()> {
        let agg = self.agg()?;
        let value = self.term()?;
        let key = self.str()?;
        let window = self.window()?;
        let scope = self.scope()?;
        let cap = self.q()?;
        let oe = self.on_exceed()?;
        m.insert("agg".into(), json!(agg));
        m.insert("value".into(), value);
        m.insert("key".into(), json!(key));
        m.insert("window".into(), window);
        m.insert("scope".into(), scope);
        m.insert("cap".into(), cap);
        m.insert("onExceed".into(), json!(oe));
        Ok(())
    }
    fn ceil(&mut self) -> D<Value> {
        self.expect(610, "ceiling")?;
        let bid = self.str()?;
        let sel_gids = self.strs()?;
        let sel_verbs = self.strs()?;
        self.expect(450, "bound core")?;
        let mut m = Map::new();
        m.insert("bid".into(), json!(bid));
        m.insert("selGids".into(), json!(sel_gids));
        m.insert("selVerbs".into(), json!(sel_verbs));
        self.core_into(&mut m)?;
        Ok(Value::Object(m))
    }
    fn validity(&mut self) -> D<Value> {
        let nb = self.int()?;
        let na = self.int()?;
        Ok(json!({"notBefore": nb, "notAfter": na, "maxIdle": self.int()?}))
    }
    fn deleg(&mut self) -> D<Value> {
        let md = self.int()?;
        let nrw = self.int()? == 1;
        Ok(json!({"maxDepth": md, "narrowOnly": nrw, "mayTouch": self.strs()?}))
    }
    fn cond(&mut self) -> D<Value> {
        match self.k()? {
            360 => Ok(json!({"k": "true"})),
            361 => {
                let op = self.op()?;
                let l = self.term()?;
                Ok(json!({"k": "cmp", "op": op, "l": l, "r": self.term()?}))
            }
            362 => {
                let a = self.cond()?;
                Ok(json!({"k": "and", "a": a, "b": self.cond()?}))
            }
            363 => {
                let a = self.cond()?;
                Ok(json!({"k": "or", "a": a, "b": self.cond()?}))
            }
            364 => Ok(json!({"k": "not", "c": self.cond()?})),
            n => err(format!("bad condition tag {n}")),
        }
    }
    fn part(&mut self) -> D<Value> {
        match self.k()? {
            375 => Ok(json!({"k": "exact", "id": self.str()?})),
            376 => Ok(json!({"k": "oneof", "ids": self.strs()?})),
            377 => {
                let rel = self.str()?;
                Ok(json!({"k": "related", "rel": rel, "anchor": self.str()?}))
            }
            n => err(format!("bad resource part tag {n}")),
        }
    }
    fn res(&mut self) -> D<Value> {
        match self.k()? {
            370 => Ok(json!({"k": "exact", "id": self.str()?})),
            371 => Ok(json!({"k": "oneof", "ids": self.strs()?})),
            372 => {
                let rel = self.str()?;
                Ok(json!({"k": "related", "rel": rel, "anchor": self.str()?}))
            }
            373 => Ok(json!({"k": "any", "reason": self.str()?})),
            374 => Ok(json!({"k": "all_of", "parts": self.list(|r| r.part())?})),
            n => err(format!("bad resource selector tag {n}")),
        }
    }
}

/// Decode the compiler's policy tape (after its leading status token); refuses unless the whole tape is one policy.
pub fn decode_policy(t: &[Tok]) -> Result<Value, String> {
    let mut r = TapeReader::new(t);
    if r.k()? != 650 {
        return err("policy expected".into());
    }
    let preds = r.list(|r| {
        if r.k()? != 620 {
            return err("pred".into());
        }
        let gid = r.str()?;
        let verb = r.str()?;
        let res = r.res_pat()?;
        Ok(json!({"gid": gid, "verb": verb, "res": res, "cond": r.nc()?}))
    })?;
    let prohs = r.list(|r| {
        if r.k()? != 640 {
            return err("prohibition".into());
        }
        let pid = r.str()?;
        let verbs = r.strs()?;
        let res = r.res_pat()?;
        Ok(json!({"pid": pid, "verbs": verbs, "res": res, "cond": r.nc()?}))
    })?;
    let ceils = r.list(|r| r.ceil())?;
    let escs = r.list(|r| r.nc())?;
    if r.k()? != 460 {
        return err("validity".into());
    }
    let validity = r.validity()?;
    if r.k()? != 461 {
        return err("delegation".into());
    }
    let deleg = r.deleg()?;
    if !r.done() {
        return err("trailing tokens after policy".into());
    }
    Ok(json!({"preds": preds, "prohs": prohs, "ceils": ceils, "escs": escs, "validity": validity, "deleg": deleg}))
}

/// Parse a goal tape; refuses unless the whole tape is exactly one goal.
pub fn decode_goal(t: &[Tok]) -> Result<Value, String> {
    let mut r = TapeReader::new(t);
    r.expect(480, "goal")?;
    let v = r.int()?;
    let principal = r.str()?;
    let ont_digest = r.str()?;
    let nl_digest = r.str()?;
    let sources = r.strs()?;
    let grants = r.list(|r| {
        r.expect(380, "grant")?;
        let gid = r.str()?;
        let verb = r.str()?;
        let res = r.res()?;
        Ok(json!({"gid": gid, "verb": verb, "res": res, "cond": r.cond()?}))
    })?;
    let prohibits = r.list(|r| {
        r.expect(392, "prohibit")?;
        let pid = r.str()?;
        let target = match r.k()? {
            390 => json!({"k": "verb", "verb": r.str()?}),
            391 => json!({"k": "effect", "cls": r.str()?}),
            _ => return err("bad prohibit target".into()),
        };
        let res = r.res()?;
        Ok(json!({"pid": pid, "target": target, "res": res, "cond": r.cond()?}))
    })?;
    let bounds = r.list(|r| {
        r.expect(451, "bound")?;
        let bid = r.str()?;
        let sel = match r.k()? {
            410 => json!({"k": "gids", "gids": r.strs()?}),
            411 => json!({"k": "effect", "cls": r.str()?}),
            _ => return err("bad selection".into()),
        };
        r.expect(450, "bound core")?;
        let mut m = Map::new();
        m.insert("bid".into(), json!(bid));
        m.insert("sel".into(), sel);
        r.core_into(&mut m)?;
        Ok(Value::Object(m))
    })?;
    r.expect(460, "validity")?;
    let validity = r.validity()?;
    r.expect(461, "delegation")?;
    let deleg = r.deleg()?;
    let escalate_on = r.list(|r| r.cond())?;
    let wildcard_ack = r.strs()?;
    let holes = r.list(|r| {
        r.expect(470, "hole")?;
        let hid = r.str()?;
        let q = r.str()?;
        let domain = r.strs()?;
        let affects = r.strs()?;
        Ok(json!({"hid": hid, "q": q, "domain": domain, "affects": affects, "global": r.int()? == 1}))
    })?;
    if !r.done() {
        return err("trailing tokens after goal".into());
    }
    Ok(json!({"v": v, "principal": principal, "ontDigest": ont_digest, "nlDigest": nl_digest, "sources": sources, "grants": grants,
        "prohibits": prohibits, "bounds": bounds, "validity": validity, "deleg": deleg, "escalateOn": escalate_on, "wildcardAck": wildcard_ack, "holes": holes}))
}
