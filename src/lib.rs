#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::Serialize;

pub const MAX_IMAGE: u64 = 256 * 1024 * 1024;

const STRUCT_MIN: usize = 16;

const MIN_RUN: usize = 32;

const WINDOW: usize = 32;

const MAX_NAME: usize = 512;

const MAX_REGIONS: usize = 8;

pub const EMPTY_JSON: &str = r#"{"load_address":null,"endianness":null,"pointer_size":null,"symbol_count":0,"symbols":[],"accounts":[],"services":[],"ipnet":false,"vx_version_hint":null}"#;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn label(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub name: &'static str,
    pub ptr_size: usize,
    pub entry_size: usize,
    pub name_off: usize,
    pub value_off: usize,
    pub type_off: usize,
    pub version_hint: &'static str,
}

pub const LAYOUTS: &[Layout] = &[
    Layout {
        name: "vx5",
        ptr_size: 4,
        entry_size: 16,
        name_off: 4,
        value_off: 8,
        type_off: 12,
        version_hint: "5.x",
    },
    Layout {
        name: "vx6",
        ptr_size: 4,
        entry_size: 20,
        name_off: 4,
        value_off: 8,
        type_off: 16,
        version_hint: "6.x",
    },
    Layout {
        name: "vx5_nonext",
        ptr_size: 4,
        entry_size: 12,
        name_off: 0,
        value_off: 4,
        type_off: 8,
        version_hint: "5.x",
    },
    Layout {
        name: "vx5_64",
        ptr_size: 8,
        entry_size: 32,
        name_off: 8,
        value_off: 16,
        type_off: 24,
        version_hint: "5.x",
    },
    Layout {
        name: "vx6_64",
        ptr_size: 8,
        entry_size: 40,
        name_off: 8,
        value_off: 16,
        type_off: 32,
        version_hint: "6.x",
    },
];

pub fn layout_by_name(name: &str) -> Option<&'static Layout> {
    LAYOUTS.iter().find(|l| l.name == name)
}

fn type_valid(b: u8) -> bool {
    (0x02..=0x0b).contains(&b)
}

fn type_letter(b: u8) -> char {
    let base = match b & 0x0e {
        0x02 => 'a',
        0x04 => 't',
        0x06 => 'd',
        0x08 => 'b',
        0x0a => 'c',
        _ => return '?',
    };
    if b & 1 == 1 {
        base.to_ascii_uppercase()
    } else {
        base
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub address: String,
    #[serde(rename = "type")]
    pub sym_type: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub load_address: Option<String>,
    pub endianness: Option<String>,
    pub pointer_size: Option<u32>,
    pub symbol_count: usize,
    pub symbols: Vec<Symbol>,
    pub accounts: Vec<Account>,
    pub services: Vec<String>,
    pub ipnet: bool,
    pub vx_version_hint: Option<String>,
}

impl Output {
    pub fn empty() -> Self {
        Output {
            load_address: None,
            endianness: None,
            pointer_size: None,
            symbol_count: 0,
            symbols: Vec::new(),
            accounts: Vec::new(),
            services: Vec::new(),
            ipnet: false,
            vx_version_hint: None,
        }
    }
}

/// Wind River library symbols
const ACCOUNT_ROUTINES: &[(&str, &str)] = &[
    ("loginUserAdd", "default login user table routine present"),
    ("loginUserDelete", "login user management routine present"),
    ("loginUserVerify", "login credential check routine present"),
    ("loginDefaultEncrypt", "built-in default password hash routine present"),
    ("loginEncryptInstall", "custom login hash hook routine present"),
    ("loginInit", "login facility initialization routine present"),
    ("loginPrompt", "interactive login prompt routine present"),
    ("shellLoginInstall", "shell login enforcement routine present"),
];

const SERVICE_SYMBOLS: &[(&str, &str)] = &[
    ("telnetd", "telnetd"),
    ("telnetdInit", "telnetd"),
    ("telnetdParserSet", "telnetd"),
    ("ftpd", "ftpd"),
    ("ftpdInit", "ftpd"),
    ("tftpd", "tftpd"),
    ("tftpdInit", "tftpd"),
    ("wdbDbg", "wdbrpc"),
    ("wdbrpc", "wdbrpc"),
    ("wdbInit", "wdbrpc"),
    ("rpcdInit", "rpcd"),
    ("httpd", "httpd"),
    ("httpdInit", "httpd"),
];

const IPNET_PREFIXES: &[&str] = &["ipcom_", "ipnet_"];

fn read_ptr(data: &[u8], off: usize, ptr_size: usize, endian: Endian) -> Option<u64> {
    match ptr_size {
        4 => {
            let b = data.get(off..off + 4)?;
            let arr = [b[0], b[1], b[2], b[3]];
            Some(match endian {
                Endian::Little => u32::from_le_bytes(arr),
                Endian::Big => u32::from_be_bytes(arr),
            } as u64)
        }
        8 => {
            let b = data.get(off..off + 8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(b);
            Some(match endian {
                Endian::Little => u64::from_le_bytes(arr),
                Endian::Big => u64::from_be_bytes(arr),
            })
        }
        _ => None,
    }
}

fn name_at(data: &[u8], off: usize) -> Option<&str> {
    let first = *data.get(off)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let limit = data.len().min(off + MAX_NAME + 1);
    let mut p = off;
    while p < limit {
        let c = data[p];
        if c == 0 {
            let len = p - off;
            if len >= 1 {
                return std::str::from_utf8(data.get(off..p)?).ok();
            }
            return None;
        }
        if p != off && !(0x21..=0x7e).contains(&c) {
            return None;
        }
        p += 1;
    }
    None
}

#[derive(Clone, Copy, Debug)]
struct Region {
    start: usize,
    run: usize,
}

fn entry_structural(data: &[u8], off: usize, endian: Endian, layout: &Layout) -> bool {
    let t = match data.get(off + layout.type_off) {
        Some(&b) => b,
        None => return false,
    };
    if !type_valid(t) {
        return false;
    }
    let name_ptr = match read_ptr(data, off + layout.name_off, layout.ptr_size, endian) {
        Some(p) => p,
        None => return false,
    };
    if name_ptr == 0 {
        return false;
    }
    read_ptr(data, off + layout.value_off, layout.ptr_size, endian).is_some()
}

fn structural_regions(data: &[u8], endian: Endian, layout: &Layout) -> Vec<Region> {
    let mut regions = Vec::new();
    let es = layout.entry_size;
    let step = layout.ptr_size;
    if data.len() < es {
        return regions;
    }
    let last_start = data.len() - es;
    let mut o = 0;
    while o <= last_start {
        if entry_structural(data, o, endian, layout) {
            let mut n = 1;
            let mut e = o + es;
            while e <= last_start && entry_structural(data, e, endian, layout) {
                n += 1;
                e += es;
            }
            if n >= STRUCT_MIN {
                regions.push(Region { start: o, run: n });
                if regions.len() >= MAX_REGIONS {
                    break;
                }
                o += n * es;
                continue;
            }
        }
        o += step;
    }
    regions
}

fn find_load_base(data: &[u8], endian: Endian, layout: &Layout, region: &Region) -> Option<u64> {
    let es = layout.entry_size;
    let ps = layout.ptr_size;
    let w = region.run.min(WINDOW);
    if w < 2 {
        return None;
    }

    let mut ptrs = Vec::with_capacity(w);
    for i in 0..w {
        let o = region.start + i * es;
        ptrs.push(read_ptr(data, o + layout.name_off, ps, endian)?);
    }
    let p0 = ptrs[0];
    let need = ((w * 3) / 4).max(8);

    let mut best_o0: Option<usize> = None;
    let mut best_score = 0usize;

    for o0 in 0..data.len() {
        let c = data[o0];
        if !(c.is_ascii_alphabetic() || c == b'_') {
            continue;
        }
        let l = p0 as i128 - o0 as i128;
        if l < 0 {
            continue;
        }
        let oi1 = ptrs[1] as i128 - l;
        if oi1 < 0 || oi1 as u128 >= data.len() as u128 || name_at(data, oi1 as usize).is_none() {
            continue;
        }
        let mut score = 0usize;
        for &p in &ptrs {
            let oi = p as i128 - l;
            if oi >= 0 && (oi as u128) < data.len() as u128 && name_at(data, oi as usize).is_some() {
                score += 1;
            }
        }
        if score > best_score {
            best_score = score;
            best_o0 = Some(o0);
            if score == w {
                break;
            }
        }
    }

    if best_score >= need {
        let o0 = best_o0?;
        Some((p0 as i128 - o0 as i128) as u64)
    } else {
        None
    }
}

fn entry_full_valid(
    data: &[u8],
    off: usize,
    endian: Endian,
    layout: &Layout,
    load_base: u64,
) -> bool {
    let t = match data.get(off + layout.type_off) {
        Some(&b) => b,
        None => return false,
    };
    if !type_valid(t) {
        return false;
    }
    let name_ptr = match read_ptr(data, off + layout.name_off, layout.ptr_size, endian) {
        Some(p) => p,
        None => return false,
    };
    if read_ptr(data, off + layout.value_off, layout.ptr_size, endian).is_none() {
        return false;
    }
    let soff = name_ptr as i128 - load_base as i128;
    if soff < 0 || soff as u128 >= data.len() as u128 {
        return false;
    }
    name_at(data, soff as usize).is_some()
}

fn validate_run(
    data: &[u8],
    endian: Endian,
    layout: &Layout,
    load_base: u64,
    region: &Region,
) -> Vec<Symbol> {
    let es = layout.entry_size;
    let ps = layout.ptr_size;

    let mut lo = region.start;
    while lo >= es && entry_full_valid(data, lo - es, endian, layout, load_base) {
        lo -= es;
    }

    let mut symbols = Vec::new();
    let mut o = lo;
    while o + es <= data.len() {
        if !entry_full_valid(data, o, endian, layout, load_base) {
            break;
        }
        let name_ptr = match read_ptr(data, o + layout.name_off, ps, endian) {
            Some(p) => p,
            None => break,
        };
        let value = read_ptr(data, o + layout.value_off, ps, endian).unwrap_or(0);
        let tb = data[o + layout.type_off];
        let soff = (name_ptr as i128 - load_base as i128) as usize;
        let name = match name_at(data, soff) {
            Some(s) => s.to_string(),
            None => break,
        };
        symbols.push(Symbol {
            name,
            address: format!("0x{:x}", value),
            sym_type: type_letter(tb).to_string(),
        });
        o += es;
    }
    symbols
}

fn build_output(endian: Endian, layout: &Layout, load_base: u64, symbols: Vec<Symbol>) -> Output {
    let names: BTreeSet<&str> = symbols.iter().map(|s| s.name.as_str()).collect();

    let mut accounts = Vec::new();
    for (routine, detail) in ACCOUNT_ROUTINES {
        if names.contains(routine) {
            accounts.push(Account {
                name: (*routine).to_string(),
                detail: (*detail).to_string(),
            });
        }
    }

    let mut services: BTreeSet<&str> = BTreeSet::new();
    for (sym, label) in SERVICE_SYMBOLS {
        if names.contains(sym) {
            services.insert(label);
        }
    }

    let ipnet = symbols
        .iter()
        .any(|s| IPNET_PREFIXES.iter().any(|p| s.name.starts_with(p)));

    Output {
        load_address: Some(format!("0x{:x}", load_base)),
        endianness: Some(endian.label().to_string()),
        pointer_size: Some((layout.ptr_size * 8) as u32),
        symbol_count: symbols.len(),
        symbols,
        accounts,
        services: services.into_iter().map(str::to_string).collect(),
        ipnet,
        vx_version_hint: Some(layout.version_hint.to_string()),
    }
}

pub fn analyze(data: &[u8]) -> Output {
    let mut best: Option<(usize, Endian, &Layout, u64, Vec<Symbol>)> = None;

    for &endian in &[Endian::Little, Endian::Big] {
        for layout in LAYOUTS {
            for region in structural_regions(data, endian, layout) {
                let load_base = match find_load_base(data, endian, layout, &region) {
                    Some(b) => b,
                    None => continue,
                };
                let symbols = validate_run(data, endian, layout, load_base, &region);
                let run = symbols.len();
                if run < MIN_RUN {
                    continue;
                }
                let better = match &best {
                    None => true,
                    Some((best_run, ..)) => run > *best_run,
                };
                if better {
                    best = Some((run, endian, layout, load_base, symbols));
                }
            }
        }
    }

    match best {
        None => Output::empty(),
        Some((_, endian, layout, load_base, symbols)) => {
            build_output(endian, layout, load_base, symbols)
        }
    }
}

pub fn read_image(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(MAX_IMAGE).read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn to_json(out: &Output) -> String {
    serde_json::to_string(out).unwrap_or_else(|_| EMPTY_JSON.to_string())
}
