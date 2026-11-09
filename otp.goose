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
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import encoding from "rekanalar/goose-encoding@v1.0.0";
import sha512;
import hmac;
import uri;

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
}

// default_params gives the rules of most authenticator apps: SHA-1, 6
// digits, 30 seconds.
fn default_params() -> Params {
    return Params { algo: ALGO_SHA1, digits: 6, period: 30, t0: 0, min_secret: 16 };
}

// check_params tests the rules and the secret.
fn check_params(secret: const u8[:], p: Params) -> i64 {
    if !algo_valid(p.algo) { return ERR_BAD_ALGORITHM; }
    if p.digits < 6 || p.digits > 9 { return ERR_BAD_DIGITS; }
    if p.period < 1 { return ERR_BAD_PERIOD; }
    if secret.len < 1 || secret.len < p.min_secret { return ERR_SHORT_SECRET; }
    return ERR_OK;
}

// pow10 gives 10 to the power of n.
fn pow10(n: i64) -> i64 {
    var v: i64 = 1;
    for j in n { v = v * 10; }
    return v;
}

// hotp_value gives the number of the code for the counter, and a code.
fn hotp_value(secret: const u8[:], counter: i64, p: Params) -> i64, i64 {
    let fault = check_params(secret, p);
    if fault != ERR_OK { return 0, fault; }
    if counter < 0 { return 0, ERR_BAD_COUNTER; }
    var msg: u8[8] = [0; 8];
    for j in 8 { msg[7 - j] = (counter >> (8 * j)) as! u8; }
    let mac = hmac(p.algo, secret, msg[..]);
    let at = (mac[algo_size(p.algo) - 1] & 0x0F) as i64;
    let word = ((mac[at] & 0x7F) as i64) << 24 | (mac[at + 1] as i64) << 16 |
               (mac[at + 2] as i64) << 8 | mac[at + 3];
    return word % pow10(p.digits), ERR_OK;
}

// digits_text writes the value with leading zeros into a fixed buffer.
fn digits_text(value: i64, digits: i64) -> u8[9] {
    var t: u8[9] = [0; 9];
    var v = value;
    var j = digits;
    while j > 0 {
        j = j - 1;
        t[j] = '0' + (v % 10) as! u8;
        v = v / 10;
    }
    return t;
}

// hotp adds the text of the code for the counter to the buffer. A fault
// leaves the buffer as it was.
fn hotp(out: u8[>..]&, secret: const u8[:], counter: i64, p: Params) -> i64 {
    let v, fault = hotp_value(secret, counter, p);
    if fault != ERR_OK { return fault; }
    let t = digits_text(v, p.digits);
    for j in p.digits { out.push(t[j]); }
    return ERR_OK;
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

// totp adds the text of the code for the time to the buffer.
fn totp(out: u8[>..]&, secret: const u8[:], now: i64, p: Params) -> i64 {
    let c, fault = totp_counter(now, p);
    if fault != ERR_OK { return fault; }
    return hotp(out, secret, c, p);
}

// verify_range tests the code against the counters from first to last.
// It runs every counter, so the time does not tell where a match stands.
// It gives the first counter that matched.
fn verify_range(secret: const u8[:], code: const u8[:], first: i64, last: i64, p: Params) -> i64, i64 {
    let fault = check_params(secret, p);
    if fault != ERR_OK { return 0, fault; }
    if code.len != p.digits { return 0, ERR_BAD_CODE; }
    for x in code {
        if x - '0' > 9 { return 0, ERR_BAD_CODE; }
    }
    var found: i64 = -1;
    var c = first;
    if c < 0 { c = 0; }
    while c <= last {
        let v, f = hotp_value(secret, c, p);
        if f != ERR_OK { return 0, f; }
        let t = digits_text(v, p.digits);
        var diff: u8 = 0;
        for j in p.digits { diff |= t[j] ^ code[j]; }
        if diff == 0 && found < 0 { found = c; }
        // The last counter ends the loop. A counter of I64_MAX must not
        // wrap to the smallest number.
        if c == last { break; }
        c = c + 1;
    }
    if found < 0 { return 0, ERR_NO_MATCH; }
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
    return verify_range(secret, code, counter, last, p);
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
    return verify_range(secret, code, first, last, p);
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

// random_secret adds n bytes from the random source of the operating
// system to the buffer.
fn random_secret(out: u8[>..]&, n: i64) -> i64 {
    if n < 1 || n > MAX_SECRET { return ERR_BAD_LENGTH; }
    let start = out.len;
    out.resize(start + n, 0);
    hash::random_bytes(out[start..]);
    return ERR_OK;
}
