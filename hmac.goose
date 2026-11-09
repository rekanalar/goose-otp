// HMAC (RFC 2104) over SHA-1, SHA-256 and SHA-512.
//
// The digests of SHA-1 and SHA-256 come from the goose-hash package.
// The digest of SHA-512 comes from this package.
namespace otp;

import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import sha512;

// The hash functions of the package.
const ALGO_SHA1: i64 = 0;
const ALGO_SHA256: i64 = 1;
const ALGO_SHA512: i64 = 2;

// algo_valid tells whether the number names a hash function.
fn algo_valid(algo: i64) -> bool {
    return algo >= ALGO_SHA1 && algo <= ALGO_SHA512;
}

// algo_block gives the blen size of the hash function in bytes.
fn algo_block(algo: i64) -> i64 {
    if algo == ALGO_SHA512 { return 128; }
    return 64;
}

// algo_size gives the digest size of the hash function in bytes.
fn algo_size(algo: i64) -> i64 {
    if algo == ALGO_SHA1 { return 20; }
    if algo == ALGO_SHA256 { return 32; }
    return 64;
}

// digest hashes the bytes. The digest fills the first bytes of the result.
fn digest(algo: i64, data: const u8[:]) -> u8[64] {
    var out: u8[64] = [0; 64];
    if algo == ALGO_SHA1 {
        let d = hash::sha1(data);
        for x, i in d { out[i] = x; }
    } else if algo == ALGO_SHA256 {
        let d = hash::sha256(data);
        for x, i in d { out[i] = x; }
    } else {
        out = sha512(data);
    }
    return out;
}

// hmac gives the MAC of the message under the key. The MAC fills the
// first algo_size(algo) bytes of the result.
fn hmac(algo: i64, key: const u8[:], msg: const u8[:]) -> u8[64] {
    let blen = algo_block(algo);
    let size = algo_size(algo);
    var k: u8[128] = [0; 128];
    if key.len > blen {
        let d = digest(algo, key);
        for j in size { k[j] = d[j]; }
    } else {
        for j in key.len { k[j] = key[j]; }
    }
    var inner: u8[>..] = [];
    for j in blen { inner.push(k[j] ^ 0x36); }
    for x in msg { inner.push(x); }
    let ih = digest(algo, inner[..]);
    var outer: u8[>..] = [];
    for j in blen { outer.push(k[j] ^ 0x5C); }
    for j in size { outer.push(ih[j]); }
    return digest(algo, outer[..]);
}
