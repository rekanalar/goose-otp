// SHA-512 (FIPS 180-4 section 6.4), one-shot.
//
// The goose-hash package holds no SHA-512. TOTP of RFC 6238 names it.
// The code takes no branch and no index from the bytes it hashes. Only
// the lengths steer it.
namespace otp;

import std;

let SHA512_K: u64[80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

let SHA512_IV: u64[8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

fn rotr64(x: u64, n: u64) -> u64 { x >> n | x << (64 - n) }

fn load_be64(s: const u8[:], i: i64) -> u64 {
    var v: u64 = 0;
    for j in 8 { v = v << 8 | s[i + j]; }
    return v;
}

// sha512_blocks takes whole blocks of 128 bytes into the state h.
fn sha512_blocks(h: u64[8]&, data: const u8[:]) {
    var w: u64[16] = [0; 16];
    var i = 0;
    while i + 128 <= data.len {
        let b = data[i..i + 128];
        var a = h[0];
        var bb = h[1];
        var c = h[2];
        var d = h[3];
        var e = h[4];
        var f = h[5];
        var g = h[6];
        var hh = h[7];
        for t in 80 {
            var x: u64 = 0;
            if t < 16 {
                x = load_be64(b, 8 * (t & 15));
            } else {
                let w15 = w[(t - 15) & 15];
                let w2 = w[(t - 2) & 15];
                let s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7);
                let s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6);
                x = w[t & 15] + s0 + w[(t - 7) & 15] + s1;
            }
            w[t & 15] = x;
            let t1 = hh + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + (g ^ (e & (f ^ g))) +
                     SHA512_K[t] + x;
            let t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & bb) | (c & (a | bb)));
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = bb;
            bb = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += bb;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
        i += 128;
    }
}

// sha512 gives the digest of the bytes.
fn sha512(data: const u8[:]) -> u8[64] {
    var h = SHA512_IV;
    let whole = data.len & ~127;
    sha512_blocks(h, data[..whole]);
    // The tail, the mark 0x80 and the length in bits as 16 bytes.
    var last: u8[256] = [0; 256];
    let rest = data.len - whole;
    for j in rest { last[j] = data[whole + j]; }
    last[rest] = 0x80;
    var n = 128;
    if rest >= 112 { n = 256; }
    let bits = (data.len as u64) << 3;
    for j in 8 { last[n - 1 - j] = (bits >> (8 * j as u64)) as! u8; }
    sha512_blocks(h, last[..n]);
    var out: u8[64] = [0; 64];
    for v, k in h {
        for j in 8 { out[8 * k + j] = (v >> (56 - 8 * j as u64)) as! u8; }
    }
    return out;
}
