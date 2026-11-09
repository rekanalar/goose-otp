// A QR code encoder and a PNG writer.
//
// The references are Go pquerna/otp (Key.Image, with the library
// boombuler/barcode at error level M) and Rust totp-rs (the qr feature,
// with qrcodegen-image). The encoder follows ISO/IEC 18004: byte mode,
// error level M, the smallest version from 1 to 40 that holds the text,
// and the mask of the lowest penalty. The PNG is a grayscale image with
// a quiet zone of 4 modules and stored (not compressed) data.
//
// A text of up to 2331 bytes fits. The writer refuses a larger text.
namespace otp;

import std;

// The codes of the faults of the QR code.
const ERR_QR_TOO_LONG: i64 = 13;
const ERR_BAD_SCALE: i64 = 14;

// The widest image that qr_png writes, in pixels.
const QR_MAX_PIXELS: i64 = 4096;

// qr_ecc_per_block gives the count of error words of one block of
// version v at level M.
fn qr_ecc_per_block(v: i64) -> i64 {
    let t: u8[40] = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
                     26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
    return t[v - 1];
}

// qr_block_count gives the count of blocks of version v at level M.
fn qr_block_count(v: i64) -> i64 {
    let t: u8[40] = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
                     17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
    return t[v - 1];
}

// qr_raw_words gives the count of words, data and error, of version v.
fn qr_raw_words(v: i64) -> i64 {
    var r = (16 * v + 128) * v + 64;
    if v >= 2 {
        let na = v / 7 + 2;
        r = r - ((25 * na - 10) * na - 55);
        if v >= 7 { r = r - 36; }
    }
    return r / 8;
}

// qr_data_words gives the count of data words of version v at level M.
fn qr_data_words(v: i64) -> i64 {
    return qr_raw_words(v) - qr_ecc_per_block(v) * qr_block_count(v);
}

// qr_version_for gives the smallest version that holds n bytes, or 0.
fn qr_version_for(n: i64) -> i64 {
    var v: i64 = 1;
    while v <= 40 {
        var cc: i64 = 8;
        if v >= 10 { cc = 16; }
        if 4 + cc + 8 * n <= 8 * qr_data_words(v) { return v; }
        v = v + 1;
    }
    return 0;
}

// gf_mul multiplies two numbers in the field of 256 elements with the
// polynomial 0x11D.
fn gf_mul(x: i64, y: i64) -> i64 {
    var z: i64 = 0;
    var i: i64 = 7;
    while i >= 0 {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z = z ^ (((y >> i) & 1) * x);
        i = i - 1;
    }
    return z;
}

// rs_divisor gives the generator polynomial of the degree deg without
// its leading one.
fn rs_divisor(deg: i64) -> i64[30] {
    var res: i64[30] = [0; 30];
    res[deg - 1] = 1;
    var root: i64 = 1;
    for i in deg {
        for j in deg {
            res[j] = gf_mul(res[j], root);
            if j + 1 < deg { res[j] = res[j] ^ res[j + 1]; }
        }
        root = gf_mul(root, 2);
    }
    return res;
}

// rs_remainder gives the error words of n data words that start at `at`.
fn rs_remainder(data: const u8[:], at: i64, n: i64, div: const i64[:], deg: i64) -> i64[30] {
    var res: i64[30] = [0; 30];
    for k in n {
        let factor = data[at + k] ^ res[0];
        for i in deg - 1 { res[i] = res[i + 1]; }
        res[deg - 1] = 0;
        for i in deg { res[i] = res[i] ^ gf_mul(div[i], factor); }
    }
    return res;
}

// put_bits appends the low len bits of val, high bit first, one bit per byte.
fn put_bits(bits: u8[>..]&, val: i64, len: i64) {
    var i = len - 1;
    while i >= 0 {
        bits.push(((val >> i) & 1) as! u8);
        i = i - 1;
    }
}

// qr_codewords gives the data words and the error words of the text in
// the order that the symbol holds them.
fn qr_codewords(out: u8[>..]&, text: const u8[:], v: i64) {
    let cap = qr_data_words(v);
    var bits: u8[>..] = [];
    put_bits(bits, 4, 4);
    var cc: i64 = 8;
    if v >= 10 { cc = 16; }
    put_bits(bits, text.len, cc);
    for c in text { put_bits(bits, c, 8); }
    var term = 4;
    if bits.len + term > cap * 8 { term = cap * 8 - bits.len; }
    put_bits(bits, 0, term);
    while bits.len % 8 != 0 { bits.push(0); }
    var data: u8[>..] = [];
    var i: i64 = 0;
    while i < bits.len {
        var b: i64 = 0;
        for k in 8 { b = b * 2 + bits[i + k]; }
        data.push(b as! u8);
        i = i + 8;
    }
    var fill: i64 = 0xEC;
    while data.len < cap {
        data.push(fill as! u8);
        if fill == 0xEC { fill = 0x11; } else { fill = 0xEC; }
    }
    let nb = qr_block_count(v);
    let ecpb = qr_ecc_per_block(v);
    let raw = qr_raw_words(v);
    let short_blocks = nb - raw % nb;
    let short_len = raw / nb;
    let div = rs_divisor(ecpb);
    // The error words of every block go in one buffer.
    var ecc: u8[>..] = [];
    var offsets: i64[64] = [0; 64];
    var lens: i64[64] = [0; 64];
    var at: i64 = 0;
    for j in nb {
        var dl = short_len - ecpb;
        if j >= short_blocks { dl = dl + 1; }
        offsets[j] = at;
        lens[j] = dl;
        let r = rs_remainder(data[..], at, dl, div[..], ecpb);
        for k in ecpb { ecc.push(r[k] as! u8); }
        at = at + dl;
    }
    // The words of the blocks go column by column.
    var col: i64 = 0;
    while col < short_len - ecpb + 1 {
        for j in nb {
            if col < lens[j] { out.push(data[offsets[j] + col]); }
        }
        col = col + 1;
    }
    for k in ecpb {
        for j in nb { out.push(ecc[j * ecpb + k]); }
    }
}

// set_fn sets a module of a function pattern. A place outside the
// symbol is skipped.
fn set_fn(m: u8[>..]&, f: u8[>..]&, size: i64, x: i64, y: i64, dark: bool) {
    if x < 0 || x >= size || y < 0 || y >= size { return; }
    var d: u8 = 0;
    if dark { d = 1; }
    m[y * size + x] = d;
    f[y * size + x] = 1;
}

// draw_finder draws the finder pattern and its separator around a center.
fn draw_finder(m: u8[>..]&, f: u8[>..]&, size: i64, cx: i64, cy: i64) {
    for dy in 9 {
        for dx in 9 {
            let ax = dx - 4;
            let ay = dy - 4;
            var dist = ax;
            if dist < 0 { dist = -dist; }
            var by = ay;
            if by < 0 { by = -by; }
            if by > dist { dist = by; }
            set_fn(m, f, size, cx + ax, cy + ay, dist != 2 && dist != 4);
        }
    }
}

// draw_alignment draws the alignment pattern around a center.
fn draw_alignment(m: u8[>..]&, f: u8[>..]&, size: i64, cx: i64, cy: i64) {
    for dy in 5 {
        for dx in 5 {
            let ax = dx - 2;
            let ay = dy - 2;
            var dist = ax;
            if dist < 0 { dist = -dist; }
            var by = ay;
            if by < 0 { by = -by; }
            if by > dist { dist = by; }
            set_fn(m, f, size, cx + ax, cy + ay, dist != 1);
        }
    }
}

// draw_format writes the format bits of a mask, and the dark module.
fn draw_format(m: u8[>..]&, f: u8[>..]&, size: i64, mask: i64) {
    // Level M has the format code 0.
    let data = mask;
    var rem = data;
    for i in 10 { rem = (rem << 1) ^ ((rem >> 9) * 0x537); }
    let bits = ((data << 10) | rem) ^ 0x5412;
    for i in 6 { set_fn(m, f, size, 8, i, ((bits >> i) & 1) != 0); }
    set_fn(m, f, size, 8, 7, ((bits >> 6) & 1) != 0);
    set_fn(m, f, size, 8, 8, ((bits >> 7) & 1) != 0);
    set_fn(m, f, size, 7, 8, ((bits >> 8) & 1) != 0);
    var i: i64 = 9;
    while i < 15 {
        set_fn(m, f, size, 14 - i, 8, ((bits >> i) & 1) != 0);
        i = i + 1;
    }
    for k in 8 { set_fn(m, f, size, size - 1 - k, 8, ((bits >> k) & 1) != 0); }
    i = 8;
    while i < 15 {
        set_fn(m, f, size, 8, size - 15 + i, ((bits >> i) & 1) != 0);
        i = i + 1;
    }
    set_fn(m, f, size, 8, size - 8, true);
}

// draw_version writes the version bits of a symbol of version 7 or more.
fn draw_version(m: u8[>..]&, f: u8[>..]&, size: i64, v: i64) {
    if v < 7 { return; }
    var rem = v;
    for i in 12 { rem = (rem << 1) ^ ((rem >> 11) * 0x1F25); }
    let bits = (v << 12) | rem;
    for i in 18 {
        let dark = ((bits >> i) & 1) != 0;
        let a = size - 11 + i % 3;
        let b = i / 3;
        set_fn(m, f, size, a, b, dark);
        set_fn(m, f, size, b, a, dark);
    }
}

// draw_patterns draws every function pattern of version v.
fn draw_patterns(m: u8[>..]&, f: u8[>..]&, size: i64, v: i64) {
    for i in size {
        set_fn(m, f, size, 6, i, i % 2 == 0);
        set_fn(m, f, size, i, 6, i % 2 == 0);
    }
    draw_finder(m, f, size, 3, 3);
    draw_finder(m, f, size, size - 4, 3);
    draw_finder(m, f, size, 3, size - 4);
    if v >= 2 {
        let na = v / 7 + 2;
        var step: i64 = 26;
        if v != 32 { step = (v * 4 + na * 2 + 1) / (na * 2 - 2) * 2; }
        var pos: i64[8] = [0; 8];
        pos[na - 1] = size - 7;
        var k = na - 2;
        while k >= 1 {
            pos[k] = pos[k + 1] - step;
            k = k - 1;
        }
        pos[0] = 6;
        for i in na {
            for j in na {
                let corner = (i == 0 && j == 0) || (i == 0 && j == na - 1) || (i == na - 1 && j == 0);
                if !corner { draw_alignment(m, f, size, pos[i], pos[j]); }
            }
        }
    }
    draw_format(m, f, size, 0);
    draw_version(m, f, size, v);
}

// place_words puts the words into the free modules in the zigzag order.
fn place_words(m: u8[>..]&, f: const u8[:], size: i64, words: const u8[:]) {
    var i: i64 = 0;
    var right = size - 1;
    while right >= 1 {
        if right == 6 { right = 5; }
        for vert in size {
            for j in 2 {
                let x = right - j;
                let upward = ((right + 1) & 2) == 0;
                var y = vert;
                if upward { y = size - 1 - vert; }
                if f[y * size + x] == 0 && i < words.len * 8 {
                    m[y * size + x] = (words[i >> 3] >> (7 - (i & 7))) & 1;
                    i = i + 1;
                }
            }
        }
        right = right - 2;
    }
}

// apply_mask flips the modules that the mask selects. A second call
// takes the mask off.
fn apply_mask(m: u8[>..]&, f: const u8[:], size: i64, mask: i64) {
    for y in size {
        for x in size {
            var hit = false;
            if mask == 0 { hit = (x + y) % 2 == 0; }
            else if mask == 1 { hit = y % 2 == 0; }
            else if mask == 2 { hit = x % 3 == 0; }
            else if mask == 3 { hit = (x + y) % 3 == 0; }
            else if mask == 4 { hit = (x / 3 + y / 2) % 2 == 0; }
            else if mask == 5 { hit = x * y % 2 + x * y % 3 == 0; }
            else if mask == 6 { hit = (x * y % 2 + x * y % 3) % 2 == 0; }
            else { hit = ((x + y) % 2 + x * y % 3) % 2 == 0; }
            if hit && f[y * size + x] == 0 { m[y * size + x] = m[y * size + x] ^ 1; }
        }
    }
}

// line_penalty scores the runs of one colour and the finder-like
// patterns along the rows (ls = size, ps = 1) or the columns.
fn line_penalty(m: const u8[:], size: i64, ls: i64, ps: i64) -> i64 {
    let pat_a: u8[11] = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    let pat_b: u8[11] = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    var p: i64 = 0;
    for line in size {
        var run: i64 = 1;
        var pos: i64 = 1;
        while pos < size {
            if m[line * ls + pos * ps] == m[line * ls + (pos - 1) * ps] {
                run = run + 1;
            } else {
                if run >= 5 { p = p + 3 + run - 5; }
                run = 1;
            }
            pos = pos + 1;
        }
        if run >= 5 { p = p + 3 + run - 5; }
        // The quiet zone counts as light, so a pattern may reach past the edge.
        var start: i64 = -4;
        while start + 7 <= size {
            var a = true;
            var b = true;
            for k in 11 {
                var c: u8 = 0;
                let at = start + k;
                if at >= 0 && at < size { c = m[line * ls + at * ps]; }
                if c != pat_a[k] { a = false; }
                if c != pat_b[k] { b = false; }
            }
            if a { p = p + 40; }
            if b { p = p + 40; }
            start = start + 1;
        }
    }
    return p;
}

// penalty gives the score of a symbol. A lower score scans better.
fn penalty(m: const u8[:], size: i64) -> i64 {
    var p = line_penalty(m, size, size, 1) + line_penalty(m, size, 1, size);
    var dark: i64 = 0;
    for y in size {
        for x in size {
            let c = m[y * size + x];
            if c == 1 { dark = dark + 1; }
            if x + 1 < size && y + 1 < size {
                if c == m[y * size + x + 1] && c == m[(y + 1) * size + x] && c == m[(y + 1) * size + x + 1] {
                    p = p + 3;
                }
            }
        }
    }
    let total = size * size;
    var diff = dark * 20 - total * 10;
    if diff < 0 { diff = -diff; }
    p = p + ((diff + total - 1) / total - 1) * 10;
    return p;
}

// qr_encode adds the modules of the QR code of the text to the buffer,
// one byte per module, row by row: 1 is dark and 0 is light. It gives a
// code and the count of modules on one side. A fault leaves the buffer
// as it was.
fn qr_encode(out: u8[>..]&, text: const u8[:]) -> i64, i64 {
    if text.len < 1 { return ERR_BAD_LENGTH, 0; }
    let v = qr_version_for(text.len);
    if v == 0 { return ERR_QR_TOO_LONG, 0; }
    let size = 17 + 4 * v;
    var words: u8[>..] = [];
    qr_codewords(words, text, v);
    var m: u8[>..] = [];
    var f: u8[>..] = [];
    m.resize(size * size, 0);
    f.resize(size * size, 0);
    draw_patterns(m, f, size, v);
    place_words(m, f[..], size, words[..]);
    var best: i64 = 0;
    var best_p: i64 = 0;
    for mask in 8 {
        apply_mask(m, f[..], size, mask);
        draw_format(m, f, size, mask);
        let p = penalty(m[..], size);
        apply_mask(m, f[..], size, mask);
        if mask == 0 || p < best_p { best = mask; best_p = p; }
    }
    apply_mask(m, f[..], size, best);
    draw_format(m, f, size, best);
    for c in m { out.push(c); }
    return ERR_OK, size;
}

// crc_table gives the table of the CRC-32 of PNG.
fn crc_table() -> u32[256] {
    var t: u32[256] = [0; 256];
    for n in 256 {
        var c = n as u32;
        for k in 8 {
            if c & 1 != 0 { c = 0xEDB88320 ^ (c >> 1); } else { c = c >> 1; }
        }
        t[n] = c;
    }
    return t;
}

// png_chunk adds a chunk to the buffer. The CRC covers the type and the data.
fn png_chunk(out: u8[>..]&, kind: const u8[:], data: const u8[:], table: const u32[:]) {
    let n = data.len;
    out.push(((n >> 24) & 0xFF) as! u8);
    out.push(((n >> 16) & 0xFF) as! u8);
    out.push(((n >> 8) & 0xFF) as! u8);
    out.push((n & 0xFF) as! u8);
    var c: u32 = 0xFFFFFFFF;
    for b in kind {
        out.push(b);
        c = table[((c ^ b) & 0xFF) as i64] ^ (c >> 8);
    }
    for b in data {
        out.push(b);
        c = table[((c ^ b) & 0xFF) as i64] ^ (c >> 8);
    }
    c = c ^ 0xFFFFFFFF;
    out.push(((c >> 24) & 0xFF) as! u8);
    out.push(((c >> 16) & 0xFF) as! u8);
    out.push(((c >> 8) & 0xFF) as! u8);
    out.push((c & 0xFF) as! u8);
}

// qr_png adds a PNG image of the QR code of the text to the buffer. Each
// module is scale by scale pixels, and a quiet zone of 4 modules
// surrounds the code. The image is 8 bit gray, black on white, with
// stored data. A fault leaves the buffer as it was.
fn qr_png(out: u8[>..]&, text: const u8[:], scale: i64) -> i64 {
    if scale < 1 { return ERR_BAD_SCALE; }
    var mods: u8[>..] = [];
    let code, size = qr_encode(mods, text);
    if code != ERR_OK { return code; }
    let side = size + 8;
    // Compare by division, so a huge scale cannot wrap the product.
    if scale > QR_MAX_PIXELS / side { return ERR_BAD_SCALE; }
    let w = side * scale;
    // The rows of the image, each with the filter byte 0.
    var raw: u8[>..] = [];
    var row: u8[>..] = [];
    for py in w {
        row.resize(0, 0);
        let my = py / scale - 4;
        row.push(0);
        for px in w {
            let mx = px / scale - 4;
            var c: u8 = 255;
            if my >= 0 && my < size && mx >= 0 && mx < size && mods[my * size + mx] == 1 { c = 0; }
            row.push(c);
        }
        for r in row { raw.push(r); }
    }
    // The zlib stream holds stored blocks of at most 65535 bytes.
    var z: u8[>..] = [];
    z.push(0x78);
    z.push(0x01);
    var at: i64 = 0;
    while at < raw.len {
        var n = raw.len - at;
        if n > 65535 { n = 65535; }
        var last: u8 = 0;
        if at + n == raw.len { last = 1; }
        z.push(last);
        z.push((n & 0xFF) as! u8);
        z.push(((n >> 8) & 0xFF) as! u8);
        z.push(((~n) & 0xFF) as! u8);
        z.push((((~n) >> 8) & 0xFF) as! u8);
        for k in n { z.push(raw[at + k]); }
        at = at + n;
    }
    var a: i64 = 1;
    var b: i64 = 0;
    for x in raw {
        a = (a + x) % 65521;
        b = (b + a) % 65521;
    }
    z.push(((b >> 8) & 0xFF) as! u8);
    z.push((b & 0xFF) as! u8);
    z.push(((a >> 8) & 0xFF) as! u8);
    z.push((a & 0xFF) as! u8);
    let table = crc_table();
    var head: u8[>..] = [];
    for k in 4 { head.push(((w >> (24 - 8 * k)) & 0xFF) as! u8); }
    for k in 4 { head.push(((w >> (24 - 8 * k)) & 0xFF) as! u8); }
    head.push(8);
    head.push(0);
    head.push(0);
    head.push(0);
    head.push(0);
    let sig: u8[8] = [137, 80, 78, 71, 13, 10, 26, 10];
    for s in sig { out.push(s); }
    png_chunk(out, "IHDR", head[..], table[..]);
    png_chunk(out, "IDAT", z[..], table[..]);
    var none: u8[>..] = [];
    png_chunk(out, "IEND", none[..], table[..]);
    return ERR_OK;
}
