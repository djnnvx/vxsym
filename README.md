# vxsym

A tiny standalone VxWorks firmware symbol-table parser.
`vxsym` reads a raw VxWorks firmware image, recovers its built-in symbol table,
and prints one JSON object to stdout.

## Usage

```
vxsym <raw-firmware>
```

## Expected output

One JSON object with exactly these keys:

```json
{
  "load_address": "0x10000",
  "endianness": "big",
  "pointer_size": 32,
  "symbol_count": 4213,
  "symbols": [{"name": "sysClkRateGet", "address": "0x1a40", "type": "T"}],
  "accounts": [{"name": "loginUserAdd", "detail": "default admin routine present"}],
  "services": ["telnetd", "wdbrpc"],
  "ipnet": true,
  "vx_version_hint": "6.x"
}
```

- `load_address`: lowercase hex string of the recovered load base, or `null`.
- `endianness`: `"big"`, `"little"`, or `null`.
- `pointer_size`: `32`, `64`, or `null`.
- `symbol_count`: total symbols recovered.
- `symbols`: each recovered symbol. `address` is the symbol value as a lowercase
  hex string. `type` is an nm-style letter: `T`/`t` text, `D`/`d` data,
  `B`/`b` bss, `A`/`a` absolute, `C`/`c` common. Uppercase is global.
- `accounts`: known VxWorks default login and credential routines found.
- `services`: sorted labels of built-in services whose entry points are present.
- `ipnet`: true if any symbol name starts with `ipcom_` or `ipnet_`, the
  Interpeak IPnet stack.
- `vx_version_hint`: `"5.x"`, `"6.x"`, or `null`, from the matched entry layout.

When no symbol table is found, `load_address`, `endianness`, `pointer_size` and
`vx_version_hint` are `null`, `symbol_count` is `0`, `symbols`, `accounts` and
`services` are empty, and `ipnet` is `false`.

## Credit

The symbol-table recovery heuristic is modeled on VxHunter. See `SOURCES.md`.
My goal here is to just use it outisde of a debugger.:)
