// Tests build synthetic VxWorks images in memory, then check the parser
// recovers the exact load base, endianness, pointer size and symbols.

use vxsym::{analyze, layout_by_name, to_json, Endian, Layout, Output};

struct Sym {
    name: String,
    value: u64,
    type_byte: u8,
}

fn sym(name: &str, value: u64, type_byte: u8) -> Sym {
    Sym {
        name: name.to_string(),
        value,
        type_byte,
    }
}

fn write_ptr(buf: &mut [u8], off: usize, val: u64, ptr_size: usize, endian: Endian) {
    match ptr_size {
        4 => {
            let v = val as u32;
            let b = match endian {
                Endian::Little => v.to_le_bytes(),
                Endian::Big => v.to_be_bytes(),
            };
            buf[off..off + 4].copy_from_slice(&b);
        }
        8 => {
            let b = match endian {
                Endian::Little => val.to_le_bytes(),
                Endian::Big => val.to_be_bytes(),
            };
            buf[off..off + 8].copy_from_slice(&b);
        }
        _ => panic!("bad pointer size in test"),
    }
}

/// Build an image: optional leading noise, then the string blob, then the
/// symbol table. The name pointer of each entry is load_base plus the file
/// offset of its string, which is how a real dumped table points at its names.
fn build_image(
    endian: Endian,
    layout: &Layout,
    load_base: u64,
    lead_pad: usize,
    syms: &[Sym],
) -> Vec<u8> {
    let mut img = vec![0xAAu8; lead_pad];

    let mut name_off = Vec::with_capacity(syms.len());
    for s in syms {
        name_off.push(img.len());
        img.extend_from_slice(s.name.as_bytes());
        img.push(0);
    }

    while !img.len().is_multiple_of(8) {
        img.push(0);
    }

    let table_off = img.len();
    img.resize(table_off + syms.len() * layout.entry_size, 0);

    for (i, s) in syms.iter().enumerate() {
        let base = table_off + i * layout.entry_size;
        let name_ptr = load_base + name_off[i] as u64;
        write_ptr(
            &mut img,
            base + layout.name_off,
            name_ptr,
            layout.ptr_size,
            endian,
        );
        write_ptr(
            &mut img,
            base + layout.value_off,
            s.value,
            layout.ptr_size,
            endian,
        );
        img[base + layout.type_off] = s.type_byte;
    }

    img
}

fn filler(count: usize) -> Vec<Sym> {
    (0..count)
        .map(|i| sym(&format!("func_{:03}", i), 0x1000 + (i as u64) * 4, 0x05))
        .collect()
}

fn assert_roundtrip(
    endian: Endian,
    layout_name: &str,
    load_base: u64,
    lead_pad: usize,
    syms: &[Sym],
) {
    let layout = layout_by_name(layout_name).unwrap();
    let img = build_image(endian, layout, load_base, lead_pad, syms);
    let out = analyze(&img);

    assert_eq!(
        out.load_address.as_deref(),
        Some(format!("0x{:x}", load_base).as_str()),
        "load address, layout {layout_name}"
    );
    assert_eq!(out.endianness.as_deref(), Some(endian.label_for_test()));
    assert_eq!(out.pointer_size, Some((layout.ptr_size * 8) as u32));
    assert_eq!(out.vx_version_hint.as_deref(), Some(layout.version_hint));
    assert_eq!(out.symbol_count, syms.len());
    assert_eq!(out.symbols.len(), syms.len());

    for (i, s) in syms.iter().enumerate() {
        let got = &out.symbols[i];
        assert_eq!(got.name, s.name, "name at {i}");
        assert_eq!(got.address, format!("0x{:x}", s.value), "address at {i}");
    }
}

// Small helper so the test file does not reach into private items.
trait EndianLabel {
    fn label_for_test(&self) -> &'static str;
}
impl EndianLabel for Endian {
    fn label_for_test(&self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

#[test]
fn recovers_little_endian_32() {
    assert_roundtrip(Endian::Little, "vx5", 0x10000, 0, &filler(40));
}

#[test]
fn recovers_big_endian_32() {
    let mut syms = filler(36);
    syms[1].type_byte = 0x07; // data, global -> D
    syms[2].type_byte = 0x09; // bss, global  -> B
    let layout = layout_by_name("vx5").unwrap();
    let img = build_image(Endian::Big, layout, 0x1000, 0, &syms);
    let out = analyze(&img);

    assert_eq!(out.endianness.as_deref(), Some("big"));
    assert_eq!(out.pointer_size, Some(32));
    assert_eq!(out.load_address.as_deref(), Some("0x1000"));
    assert_eq!(out.symbols[0].sym_type, "T");
    assert_eq!(out.symbols[1].sym_type, "D");
    assert_eq!(out.symbols[2].sym_type, "B");
}

#[test]
fn recovers_64bit() {
    assert_roundtrip(Endian::Little, "vx5_64", 0x100000, 0, &filler(40));
}

#[test]
fn recovers_64bit_big_endian_vx6() {
    assert_roundtrip(Endian::Big, "vx6_64", 0x80000000, 0, &filler(40));
}

#[test]
fn recovers_vx6_layout_hint() {
    assert_roundtrip(Endian::Little, "vx6", 0x20000, 0, &filler(40));
}

#[test]
fn recovers_with_leading_padding() {
    // Strings do not start at offset 0, so the load base must be derived, not
    // assumed to equal the first name pointer.
    assert_roundtrip(Endian::Little, "vx5", 0x30000, 777, &filler(40));
}

#[test]
fn type_letters_match_nm() {
    let syms = vec![
        sym("absLocal", 0x10, 0x02),   // a
        sym("absGlobal", 0x11, 0x03),  // A
        sym("textLocal", 0x12, 0x04),  // t
        sym("textGlobal", 0x13, 0x05), // T
        sym("dataLocal", 0x14, 0x06),  // d
        sym("dataGlobal", 0x15, 0x07), // D
        sym("bssLocal", 0x16, 0x08),   // b
        sym("bssGlobal", 0x17, 0x09),  // B
        sym("commLocal", 0x18, 0x0a),  // c
        sym("commGlobal", 0x19, 0x0b), // C
    ];
    let mut all = syms;
    all.extend(filler(30));
    let layout = layout_by_name("vx5").unwrap();
    let img = build_image(Endian::Little, layout, 0x10000, 0, &all);
    let out = analyze(&img);

    let letters: Vec<&str> = out.symbols[..10]
        .iter()
        .map(|s| s.sym_type.as_str())
        .collect();
    assert_eq!(
        letters,
        vec!["a", "A", "t", "T", "d", "D", "b", "B", "c", "C"]
    );
}

#[test]
fn intelligence_tables_fire() {
    let mut syms = vec![
        sym("loginUserAdd", 0x2000, 0x05),
        sym("loginDefaultEncrypt", 0x2010, 0x05),
        sym("telnetd", 0x2020, 0x05),
        sym("ftpdInit", 0x2030, 0x05),
        sym("wdbrpc", 0x2040, 0x05),
        sym("ipnet_tcp_input", 0x2050, 0x05),
        sym("ipcom_drv_init", 0x2060, 0x05),
        sym("nothingSpecial", 0x2070, 0x05),
    ];
    syms.extend(filler(30));

    let layout = layout_by_name("vx5").unwrap();
    let img = build_image(Endian::Little, layout, 0x10000, 0, &syms);
    let out = analyze(&img);

    let account_names: Vec<&str> = out.accounts.iter().map(|a| a.name.as_str()).collect();
    assert!(account_names.contains(&"loginUserAdd"));
    assert!(account_names.contains(&"loginDefaultEncrypt"));
    assert_eq!(out.accounts.len(), 2);
    assert!(out.accounts.iter().all(|a| !a.detail.is_empty()));

    assert_eq!(out.services, vec!["ftpd", "telnetd", "wdbrpc"]);
    assert!(out.ipnet);
}

#[test]
fn no_ipnet_without_prefix() {
    let out = analyze(&build_image(
        Endian::Little,
        layout_by_name("vx5").unwrap(),
        0x10000,
        0,
        &filler(40),
    ));
    assert!(!out.ipnet);
    assert!(out.services.is_empty());
    assert!(out.accounts.is_empty());
}

#[test]
fn empty_input_is_empty_shape() {
    let out = analyze(&[]);
    assert_eq!(out, Output::empty());
    assert_eq!(out.load_address, None);
    assert_eq!(out.endianness, None);
    assert_eq!(out.pointer_size, None);
    assert_eq!(out.symbol_count, 0);
    assert!(out.symbols.is_empty());
    assert!(out.accounts.is_empty());
    assert!(out.services.is_empty());
    assert!(!out.ipnet);
    assert_eq!(out.vx_version_hint, None);
}

#[test]
fn empty_json_matches_serializer() {
    assert_eq!(to_json(&Output::empty()), vxsym::EMPTY_JSON);
}

#[test]
fn near_miss_below_min_run_is_rejected() {
    // A well-formed table of only 20 entries is below the minimum run, so it
    // must be rejected and yield the empty shape.
    let out = analyze(&build_image(
        Endian::Little,
        layout_by_name("vx5").unwrap(),
        0x10000,
        0,
        &filler(20),
    ));
    assert_eq!(out, Output::empty());
}

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.next_u64() & 0xff) as u8;
        }
    }
}

fn assert_shape_consistent(out: &Output) {
    assert_eq!(out.symbol_count, out.symbols.len());
    if out.load_address.is_none() {
        assert_eq!(out.symbol_count, 0);
        assert!(out.symbols.is_empty());
        assert!(!out.ipnet);
        assert!(out.endianness.is_none());
        assert!(out.pointer_size.is_none());
        assert!(out.vx_version_hint.is_none());
        assert!(out.accounts.is_empty());
        assert!(out.services.is_empty());
    }
    // Serialization must always succeed.
    assert!(to_json(out).starts_with('{'));
}

#[test]
fn random_buffers_do_not_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..2000 {
        let len = (rng.next_u64() % 4096) as usize;
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        let out = analyze(&buf);
        // Pure random data must not be mistaken for a symbol table.
        assert_eq!(out, Output::empty());
        assert_shape_consistent(&out);
    }
}

#[test]
fn truncated_image_does_not_panic() {
    let layout = layout_by_name("vx5").unwrap();
    let img = build_image(Endian::Little, layout, 0x10000, 0, &filler(50));
    for cut in [0usize, 1, 7, 17, 64, 200, img.len() / 2, img.len() - 1] {
        let cut = cut.min(img.len());
        let out = analyze(&img[..cut]);
        assert_shape_consistent(&out);
    }
}

#[test]
fn garbage_prefix_then_table_still_found() {
    // A block of invalid bytes before the real table must not stop recovery.
    let layout = layout_by_name("vx5").unwrap();
    let mut img = vec![0u8; 0]; // built below with lead_pad noise
    img.extend(build_image(
        Endian::Little,
        layout,
        0x40000,
        4096,
        &filler(40),
    ));
    let out = analyze(&img);
    assert_eq!(out.load_address.as_deref(), Some("0x40000"));
    assert_eq!(out.symbol_count, 40);
}
