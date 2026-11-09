// otp - HOTP and TOTP one-time passwords for Goose.
//
// The package builds and checks the codes of RFC 4226 (HOTP) and RFC
// 6238 (TOTP), with SHA-1, SHA-256 and SHA-512. A call that can fail
// gives a code. The code ERR_OK means that the call succeeded.
//
// The package holds no clock. The caller gives the time as the count of
// seconds since 1970-01-01 UTC.
//
// The repository is goose-otp. The import name is "otp".
namespace otp;

import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import encoding from "rekanalar/goose-encoding@v1.0.0";
import sha512;
import hmac;
import uri;
import qr;

// The codes of the faults.
const ERR_OK: i64 = 0;
const ERR_BAD_DIGITS: i64 = 1;
const ERR_BAD_ALGORITHM: i64 = 2;
const ERR_BAD_PERIOD: i64 = 3;
const ERR_SHORT_SECRET: i64 = 4;
const ERR_BAD_COUNTER: i64 = 5;
const ERR_BAD_CODE: i64 = 6;
const ERR_NO_MATCH: i64 = 7;
const ERR_BAD_SECRET_TEXT: i64 = 8;
const ERR_BAD_WINDOW: i64 = 9;
const ERR_BAD_LENGTH: i64 = 10;

// error_text names a code.
fn error_text(code: i64) -> const u8[:] {
    if code == ERR_OK { return "ok"; }
    if code == ERR_BAD_DIGITS { return "the count of digits is not from 6 to 9"; }
    if code == ERR_BAD_ALGORITHM { return "the hash function is not known"; }
    if code == ERR_BAD_PERIOD { return "the period is not positive"; }
    if code == ERR_SHORT_SECRET { return "the secret is shorter than the minimum"; }
    if code == ERR_BAD_COUNTER { return "the counter or the time is negative"; }
    if code == ERR_BAD_CODE { return "the code is not made of the right count of digits"; }
    if code == ERR_NO_MATCH { return "the code matches no counter in the window"; }
    if code == ERR_BAD_SECRET_TEXT { return "the secret text is not valid base32"; }
    if code == ERR_BAD_WINDOW { return "the window is negative or larger than the limit"; }
    if code == ERR_BAD_LENGTH { return "the length is not from 1 to the limit"; }
    if code == ERR_QR_TOO_LONG { return "the text does not fit in a QR code"; }
    if code == ERR_BAD_SCALE { return "the scale is below 1 or the image is too wide"; }
    return "unknown code";
}

// The largest window that a verify call takes. A larger window costs
// more HMAC calls and gives an attacker more codes to guess with.
const MAX_WINDOW: i64 = 1000;

// The largest count of random bytes that random_secret writes.
const MAX_SECRET: i64 = 1024;

// Params holds the rules of a code.
struct Params {
    // The hash function: ALGO_SHA1, ALGO_SHA256 or ALGO_SHA512.
    algo: i64,
    // The count of digits, from 6 to 9.
    digits: i64,
    // The seconds of one step of TOTP.
    period: i64,
    // The time of the first step of TOTP, in seconds since 1970.
    t0: i64,
    // The shortest secret that the package takes, in bytes. RFC 4226
    // asks for 16 bytes at least.
    min_secret: i64,
    // True for the codes of Steam: SHA-1, and letters of the Steam
    // alphabet in place of digits. The field digits must be 5.
    steam: bool,
}

// default_params gives the rules of most authenticator apps: SHA-1, 6
// digits, 30 seconds.
fn default_params() -> Params {
    return Params { algo: ALGO_SHA1, digits: 6, period: 30, t0: 0, min_secret: 16, steam: false };
}

// steam_params gives the rules of Steam Guard: SHA-1, 5 characters, 30
// seconds. Steam takes no other count of characters.
fn steam_params() -> Params {
    return Params { algo: ALGO_SHA1, digits: 5, period: 30, t0: 0, min_secret: 16, steam: true };
}

// The alphabet of the codes of Steam.
const STEAM_CHARS: const u8[:] = "23456789BCDFGHJKMNPQRTVWXY";

// steam_char tells whether a byte is in the alphabet of Steam.
fn steam_char(c: u8) -> bool {
    for x in STEAM_CHARS { if x == c { return true; } }
    return false;
}

// check_params tests the rules and the secret.
fn check_params(secret: const u8[:], p: Params) -> i64 {
    if !algo_valid(p.algo) { return ERR_BAD_ALGORITHM; }
    if p.steam {
        // Both references give 5 characters and no other count. A code
        // of fewer characters has too few values to guess against.
        if p.algo != ALGO_SHA1 { return ERR_BAD_ALGORITHM; }
        if p.digits != 5 { return ERR_BAD_DIGITS; }
    } else if p.digits < 6 || p.digits > 9 {
        return ERR_BAD_DIGITS;
    }
    if p.period < 1 { return ERR_BAD_PERIOD; }
    if secret.len < 1 || secret.len < p.min_secret { return ERR_SHORT_SECRET; }
    return ERR_OK;
}

// pow26 gives 26 to the power of n.
fn pow26(n: i64) -> i64 {
    var v: i64 = 1;
    for j in n { v = v * 26; }
    return v;
}

// pow10 gives 10 to the power of n.
fn pow10(n: i64) -> i64 {
    var v: i64 = 1;
    for j in n { v = v * 10; }
    return v;
}

// hotp_value gives the number of the code for the counter, and a code.
fn hotp_value(secret: const u8[:], counter: i64, p: Params) -> i64, i64 {
    if counter < 0 {
        let fault = check_params(secret, p);
        if fault != ERR_OK { return 0, fault; }
        return 0, ERR_BAD_COUNTER;
    }
    return hotp_value_u64(secret, counter as u64, p);
}

// hotp_value_u64 does the work of hotp_value for the full 64 bit counter
// of RFC 4226.
fn hotp_value_u64(secret: const u8[:], counter: u64, p: Params) -> i64, i64 {
    let fault = check_params(secret, p);
    if fault != ERR_OK { return 0, fault; }
    var msg: u8[8] = [0; 8];
    for j in 8 { msg[7 - j] = (counter >> (8 * j)) as! u8; }
    let mac = hmac(p.algo, secret, msg[..]);
    let at = (mac[algo_size(p.algo) - 1] & 0x0F) as i64;
    let word = ((mac[at] & 0x7F) as i64) << 24 | (mac[at + 1] as i64) << 16 |
               (mac[at + 2] as i64) << 8 | mac[at + 3];
    if p.steam { return word % pow26(p.digits), ERR_OK; }
    return word % pow10(p.digits), ERR_OK;
}

// digits_text writes the code into a fixed buffer. A number gets
// leading zeros. A code of Steam takes its characters from the lowest
// part of the value up, as Python pyotp and Rust totp-rs do.
fn digits_text(value: i64, p: Params) -> u8[9] {
    var t: u8[9] = [0; 9];
    var v = value;
    // The count is at most 9 for every rule that check_params takes.
    // The clamp keeps a direct call with a wild count inside the array.
    var count = p.digits;
    if count > 9 { count = 9; }
    if count < 0 { count = 0; }
    if p.steam {
        for j in count {
            t[j] = STEAM_CHARS[v % 26];
            v = v / 26;
        }
        return t;
    }
    var j = count;
    while j > 0 {
        j = j - 1;
        t[j] = '0' + (v % 10) as! u8;
        v = v / 10;
    }
    return t;
}

// totp_offset adds the text of the code for a time with the counter
// moved by offset steps. The offset may be negative. The Python library
// pyotp takes an offset on its at() call.
fn totp_offset(out: u8[>..]&, secret: const u8[:], now: i64, offset: i64, p: Params) -> i64 {
    let c, fault = totp_counter(now, p);
    if fault != ERR_OK { return fault; }
    // The counter must not wrap.
    if offset > 0 && c > 9223372036854775807 - offset { return ERR_BAD_COUNTER; }
    if offset < 0 && c < -offset { return ERR_BAD_COUNTER; }
    return hotp(out, secret, c + offset, p);
}

// hotp adds the text of the code for the counter to the buffer. A fault
// leaves the buffer as it was.
fn hotp(out: u8[>..]&, secret: const u8[:], counter: i64, p: Params) -> i64 {
    let v, fault = hotp_value(secret, counter, p);
    if fault != ERR_OK { return fault; }
    let t = digits_text(v, p);
    for j in p.digits { out.push(t[j]); }
    return ERR_OK;
}

// hotp_u64 adds the text of the code for a counter of the full range of
// RFC 4226, 0 to 2 to the power of 64 minus 1. Go pquerna/otp and Rust
// totp-rs take this range. A fault leaves the buffer as it was.
fn hotp_u64(out: u8[>..]&, secret: const u8[:], counter: u64, p: Params) -> i64 {
    let v, fault = hotp_value_u64(secret, counter, p);
    if fault != ERR_OK { return fault; }
    let t = digits_text(v, p);
    for j in p.digits { out.push(t[j]); }
    return ERR_OK;
}

// hotp_verify_u64 tests the code against the counter and the next
// `ahead` counters of the full 64 bit range. It gives the counter that
// matched. The window stops at the largest counter and does not wrap.
fn hotp_verify_u64(secret: const u8[:], code: const u8[:], counter: u64, ahead: i64, p: Params) -> u64, i64 {
    if ahead < 0 || ahead > MAX_WINDOW { return 0, ERR_BAD_WINDOW; }
    var last: u64 = 18446744073709551615;
    if counter <= last - (ahead as u64) { last = counter + (ahead as u64); }
    return verify_range(secret, code, counter, last, p);
}

// totp_counter gives the step of the time.
fn totp_counter(now: i64, p: Params) -> i64, i64 {
    if p.period < 1 { return 0, ERR_BAD_PERIOD; }
    if now < p.t0 { return 0, ERR_BAD_COUNTER; }
    // The difference must not wrap. A t0 below zero and a now above
    // I64_MAX + t0 give a difference that no i64 holds.
    if p.t0 < 0 && now > 9223372036854775807 + p.t0 { return 0, ERR_BAD_COUNTER; }
    return (now - p.t0) / p.period, ERR_OK;
}

// totp_next_step gives the time of the first second of the next step,
// as Rust totp-rs next_step does.
fn totp_next_step(now: i64, p: Params) -> i64, i64 {
    let c, fault = totp_counter(now, p);
    if fault != ERR_OK { return 0, fault; }
    // The seconds left come from a difference that totp_counter checked.
    // The next step is now plus those seconds, and it must not wrap.
    let left = p.period - (now - p.t0) % p.period;
    if now > 9223372036854775807 - left { return 0, ERR_BAD_COUNTER; }
    return now + left, ERR_OK;
}

// totp_ttl gives the seconds that the code of the time stays valid, as
// Rust totp-rs ttl does.
fn totp_ttl(now: i64, p: Params) -> i64, i64 {
    let c, fault = totp_counter(now, p);
    if fault != ERR_OK { return 0, fault; }
    return p.period - (now - p.t0) % p.period, ERR_OK;
}

// totp adds the text of the code for the time to the buffer.
fn totp(out: u8[>..]&, secret: const u8[:], now: i64, p: Params) -> i64 {
    let c, fault = totp_counter(now, p);
    if fault != ERR_OK { return fault; }
    return hotp(out, secret, c, p);
}

// verify_range tests the code against the counters from first to last.
// It runs every counter, so the time does not tell where a match stands.
// It gives the first counter that matched.
fn verify_range(secret: const u8[:], code: const u8[:], first: u64, last: u64, p: Params) -> u64, i64 {
    let fault = check_params(secret, p);
    if fault != ERR_OK { return 0, fault; }
    if code.len != p.digits { return 0, ERR_BAD_CODE; }
    for x in code {
        if p.steam {
            if !steam_char(x) { return 0, ERR_BAD_CODE; }
        } else if x - '0' > 9 {
            return 0, ERR_BAD_CODE;
        }
    }
    var found: u64 = 0;
    var has = false;
    var c = first;
    while c <= last {
        let v, f = hotp_value_u64(secret, c, p);
        if f != ERR_OK { return 0, f; }
        let t = digits_text(v, p);
        var diff: u8 = 0;
        for j in p.digits { diff |= t[j] ^ code[j]; }
        if diff == 0 && !has { found = c; has = true; }
        // The last counter ends the loop. A counter of I64_MAX must not
        // wrap to the smallest number.
        if c == last { break; }
        c = c + 1;
    }
    if !has { return 0, ERR_NO_MATCH; }
    return found, ERR_OK;
}

// hotp_verify tests the code against the counter and the next `ahead`
// counters. It gives the counter that matched, so the caller can store
// counter + 1 and refuse a reuse.
fn hotp_verify(secret: const u8[:], code: const u8[:], counter: i64, ahead: i64, p: Params) -> i64, i64 {
    if ahead < 0 || ahead > MAX_WINDOW { return 0, ERR_BAD_WINDOW; }
    if counter < 0 { return 0, ERR_BAD_COUNTER; }
    // The last counter must not wrap.
    var last = 9223372036854775807;
    if counter <= 9223372036854775807 - ahead { last = counter + ahead; }
    let m, f = verify_range(secret, code, counter as u64, last as u64, p);
    return m as i64, f;
}

// totp_verify tests the code against the step of the time, `back` steps
// before it and `ahead` steps after it. It gives the step that matched.
// The caller stores that step and refuses a step that is not larger.
fn totp_verify(secret: const u8[:], code: const u8[:], now: i64, back: i64, ahead: i64, p: Params) -> i64, i64 {
    if back < 0 || ahead < 0 || back > MAX_WINDOW || ahead > MAX_WINDOW {
        return 0, ERR_BAD_WINDOW;
    }
    let c, fault = totp_counter(now, p);
    if fault != ERR_OK { return 0, fault; }
    // The last step must not wrap. The first step may fall below zero;
    // the range starts at zero then.
    var last = 9223372036854775807;
    if c <= 9223372036854775807 - ahead { last = c + ahead; }
    var first = c - back;
    if first < 0 { first = 0; }
    let m, f = verify_range(secret, code, first as u64, last as u64, p);
    return m as i64, f;
}

// now_seconds gives the wall clock in seconds since 1970. It is the
// time that pyotp now() and totp-rs generate_current use.
fn now_seconds() -> i64 {
    return time_ns() / 1000000000;
}

// totp_now adds the code for the time of the wall clock to the buffer.
fn totp_now(out: u8[>..]&, secret: const u8[:], p: Params) -> i64 {
    return totp(out, secret, now_seconds(), p);
}

// totp_verify_now tests the code against the wall clock, as totp_verify
// does for a time that the caller gives.
fn totp_verify_now(secret: const u8[:], code: const u8[:], back: i64, ahead: i64, p: Params) -> i64, i64 {
    return totp_verify(secret, code, now_seconds(), back, ahead, p);
}

// secret_decode adds the bytes of a base32 secret to the buffer. It
// takes either case, no padding and the spaces that apps show.
fn secret_decode(out: u8[>..]&, text: const u8[:]) -> i64 {
    var opts = encoding::text_options();
    opts.padding = false;
    let code, pos = encoding::base32_decode(out, text, opts);
    if code != encoding::ERR_OK { return ERR_BAD_SECRET_TEXT; }
    return ERR_OK;
}

// secret_encode adds the base32 text of a secret, with no padding, to
// the buffer.
fn secret_encode(out: u8[>..]&, secret: const u8[:]) {
    var opts = encoding::strict_options();
    opts.padding = false;
    encoding::base32_encode(out, secret, opts);
}

// random_secret_text adds the base32 text of n random bytes to the
// buffer. The text has no padding. The Python library pyotp gives the
// same form with random_base32.
fn random_secret_text(out: u8[>..]&, n: i64) -> i64 {
    let fault = random_secret(out, n);
    if fault != ERR_OK { return fault; }
    // The text stands after the bytes. The bytes go first.
    let bytes = out.len - n;
    var text: u8[>..] = [];
    secret_encode(text, out[bytes..]);
    out.resize(bytes, 0);
    for c in text { out.push(c); }
    return ERR_OK;
}

// random_secret_hex adds the upper case hex text of n random bytes to
// the buffer. The Python library pyotp gives a text of hex digits with
// random_hex.
fn random_secret_hex(out: u8[>..]&, n: i64) -> i64 {
    var raw: u8[>..] = [];
    let fault = random_secret(raw, n);
    if fault != ERR_OK { return fault; }
    var opts = encoding::strict_options();
    opts.lower = false;
    encoding::hex_encode(out, raw[..], opts);
    return ERR_OK;
}

// random_secret adds n bytes from the random source of the operating
// system to the buffer.
fn random_secret(out: u8[>..]&, n: i64) -> i64 {
    if n < 1 || n > MAX_SECRET { return ERR_BAD_LENGTH; }
    let start = out.len;
    out.resize(start + n, 0);
    hash::random_bytes(out[start..]);
    return ERR_OK;
}
