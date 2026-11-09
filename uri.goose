// The otpauth:// URI of the Google Authenticator key format.
//
// The references are Python pyotp 2.10.0, Go pquerna/otp and Node
// otplib 12.0.1. They were read and run on 2026-11-09.
//
// The build writes otpauth://TYPE/LABEL?secret=... and one parameter
// for every rule that differs from the default of RFC 6238. The read
// is strict: it refuses a scheme or a type that is not otpauth or
// totp/hotp, a secret that is not base32, an algorithm that is not one
// of the three, a count of digits outside 6 to 9, a period of less
// than one, an issuer that differs between the label and the query,
// and a key that it does not know.
//
// The read splits the label on the colon before it decodes the parts.
// The percent signs stay literal, so a name that holds an encoded
// colon stays one name.
//
// Every text of the result lives in the buffer of the caller. The
// result holds the place of each text in that buffer.
namespace otp;

import std;
import encoding from "rekanalar/goose-encoding@v1.0.0";
import encoding from "rekanalar/goose-encoding@v1.0.0";

// The codes of the faults of the URI.
const ERR_BAD_URI: i64 = 11;
const ERR_NO_ISSUER: i64 = 12;

// uri_error_text names a code of the URI.
fn uri_error_text(code: i64) -> const u8[:] {
    if code == ERR_BAD_URI { return "the otpauth URI is not valid"; }
    if code == ERR_NO_ISSUER { return "the issuer or the account name is empty"; }
    return "unknown code";
}

// UriParams holds the parts of a URI that the read finds. Each text
// stands in the buffer of the caller between its place and its length.
struct UriParams {
    // True for totp, false for hotp.
    totp: bool,
    // The place and the length of the account name.
    name_at: i64,
    name_len: i64,
    // The place and the length of the issuer of the label.
    issuer_at: i64,
    issuer_len: i64,
    // The place and the length of the issuer of the query.
    issuer_q_at: i64,
    issuer_q_len: i64,
    // The place and the length of the secret text, in base32.
    secret_at: i64,
    secret_len: i64,
    // The place and the length of the algorithm name.
    algo_at: i64,
    algo_len: i64,
    // The count of digits, or 0 when the query holds none.
    digits: i64,
    // The period, or 0 when the query holds none.
    period: i64,
    // The counter, or -1 when the query holds none.
    counter: i64,
}

// hex_digit gives the value of a hex digit, or -1.
fn hex_digit(c: u8) -> i64 {
    if c - '0' < 10 { return c - '0'; }
    if c - 'a' < 6 { return c - 'a' + 10; }
    if c - 'A' < 6 { return c - 'A' + 10; }
    return -1;
}

// uri_unescape appends the decoded text of one percent-escaped part.
// A percent sign not followed by two hex digits stays a literal.
fn uri_unescape(out: u8[>..]&, s: const u8[:]) {
    var i: i64 = 0;
    while i < s.len {
        if s[i] == '%' && i + 2 < s.len && hex_digit(s[i + 1]) >= 0 && hex_digit(s[i + 2]) >= 0 {
            out.push((hex_digit(s[i + 1]) * 16 + hex_digit(s[i + 2])) as u8);
            i = i + 3;
        } else {
            out.push(s[i]);
            i = i + 1;
        }
    }
}

// uri_escape appends the percent-escaped form of s. Letters, digits and
// the marks - . _ ~ stay. Every other byte becomes %XX with upper case
// hex digits, as pyotp and otplib write.
fn uri_escape(out: u8[>..]&, s: const u8[:]) {
    for c in s {
        if c - 'a' < 26 || c - 'A' < 26 || c - '0' < 10 || c == '-' || c == '.' ||
           c == '_' || c == '~' {
            out.push(c);
        } else {
            out.push('%');
            let h = (c >> 4) as i64;
            let l = (c & 0x0F) as i64;
            var hb = '0' + h as u8;
            var lb = '0' + l as u8;
            if h > 9 { hb = 'A' + (h - 10) as u8; }
            if l > 9 { lb = 'A' + (l - 10) as u8; }
            out.push(hb);
            out.push(lb);
        }
    }
}

// algo_name writes the upper case name of a hash function.
fn algo_name(algo: i64) -> const u8[:] {
    if algo == ALGO_SHA1 { return "SHA1"; }
    if algo == ALGO_SHA256 { return "SHA256"; }
    return "SHA512";
}

// algo_from_name gives the hash function of a name in any case, or -1.
fn algo_from_name(s: const u8[:]) -> i64 {
    if s.len == 4 {
        if upper(s, 0) == 'S' && upper(s, 1) == 'H' && upper(s, 2) == 'A' && upper(s, 3) == '1' {
            return ALGO_SHA1;
        }
        return -1;
    }
    if s.len == 6 {
        if upper(s, 0) == 'S' && upper(s, 1) == 'H' && upper(s, 2) == 'A' && upper(s, 3) == '2' &&
           upper(s, 4) == '5' && upper(s, 5) == '6' {
            return ALGO_SHA256;
        }
        if upper(s, 0) == 'S' && upper(s, 1) == 'H' && upper(s, 2) == 'A' && upper(s, 3) == '5' &&
           upper(s, 4) == '1' && upper(s, 5) == '2' {
            return ALGO_SHA512;
        }
        return -1;
    }
    return -1;
}

// upper gives a byte in upper case.
fn upper(s: const u8[:], i: i64) -> u8 {
    let c = s[i];
    if c - 'a' < 26 { return c - 32; }
    return c;
}

// number_of reads the bytes as a decimal number. It gives -1 on a byte
// that is not a digit, on an empty text, or on a number of more than
// 18 digits. A sign is refused.
fn number_of(s: const u8[:]) -> i64 {
    if s.len == 0 || s.len > 18 { return -1; }
    var v: i64 = 0;
    for c in s {
        if c - '0' > 9 { return -1; }
        v = v * 10 + (c - '0');
    }
    return v;
}

// digits10 appends the decimal text of a number.
fn digits10(out: u8[>..]&, v: i64) {
    if v < 0 { return; }
    var t: u8[20] = [0; 20];
    var n: i64 = 0;
    var x = v;
    while x > 0 {
        t[n] = '0' + (x % 10) as! u8;
        n = n + 1;
        x = x / 10;
    }
    if n == 0 { out.push('0'); }
    var j = n - 1;
    while j >= 0 {
        out.push(t[j]);
        j = j - 1;
    }
}

// uri_build adds the otpauth URI to the buffer. It takes the secret
// text in base32, the issuer and the account name of the label. One of
// the two must stand. A parameter stands only when it differs from the
// default of SHA-1, 6 digits and 30 seconds.
fn uri_build(out: u8[>..]&, secret_text: const u8[:], issuer: const u8[:], name: const u8[:],
             counter: i64, has_counter: bool, p: Params) -> i64 {
    if secret_text.len == 0 { return ERR_SHORT_SECRET; }
    if issuer.len == 0 && name.len == 0 { return ERR_NO_ISSUER; }
    // The URI of Steam is not part of the package.
    if p.steam { return ERR_BAD_ALGORITHM; }
    if p.algo < ALGO_SHA1 || p.algo > ALGO_SHA512 { return ERR_BAD_ALGORITHM; }
    if p.digits < 6 || p.digits > 9 { return ERR_BAD_DIGITS; }
    if !has_counter && p.period < 1 { return ERR_BAD_PERIOD; }
    if has_counter && counter < 0 { return ERR_BAD_COUNTER; }
    // The secret must be base32. The text is checked before the URI
    // stands, so a bad secret never reaches the buffer of the caller.
    if !secret_ok(secret_text) { return ERR_BAD_URI; }
    for c in "otpauth://" { out.push(c); }
    if has_counter { for c in "hotp/" { out.push(c); } } else { for c in "totp/" { out.push(c); } }
    if issuer.len > 0 {
        uri_escape(out, issuer);
        out.push(':');
    }
    uri_escape(out, name);
    for c in "?secret=" { out.push(c); }
    for c in secret_text { out.push(c); }
    if issuer.len > 0 {
        for c in "&issuer=" { out.push(c); }
        uri_escape(out, issuer);
    }
    if has_counter {
        for c in "&counter=" { out.push(c); }
        digits10(out, counter);
    }
    if p.algo != ALGO_SHA1 {
        for c in "&algorithm=" { out.push(c); }
        for c in algo_name(p.algo) { out.push(c); }
    }
    if p.digits != 6 {
        for c in "&digits=" { out.push(c); }
        digits10(out, p.digits);
    }
    if !has_counter && p.period != 30 {
        for c in "&period=" { out.push(c); }
        digits10(out, p.period);
    }
    return ERR_OK;
}

// key_from_uri reads an otpauth URI into the rules and the secret. It
// fills p with the rules of the URI and writes the bytes of the secret
// to out. It is the same as the key of the Go library pquerna/otp, which
// holds the parts of a URI. A fault leaves the buffer as it was.
fn key_from_uri(text: const u8[:], out: u8[>..]&, p: Params&) -> i64 {
    var parts: u8[>..] = [];
    let code, r = uri_parse(text, parts);
    if code != ERR_OK { return code; }
    var opts = default_params();
    if r.digits > 0 { opts.digits = r.digits; }
    if r.period > 0 { opts.period = r.period; }
    if r.algo_len > 0 {
        let a = algo_from_name(parts[r.algo_at..r.algo_at + r.algo_len]);
        if a < 0 { return ERR_BAD_ALGORITHM; }
        opts.algo = a;
    }
    let secret_text = parts[r.secret_at..r.secret_at + r.secret_len];
    let base = out.len;
    var opts2 = no_pad_options();
    let sc = encoding::base32_decode(out, secret_text, opts2);
    if sc != encoding::ERR_OK { out.resize(base, 0); return ERR_BAD_SECRET_TEXT; }
    p.algo = opts.algo;
    p.digits = opts.digits;
    p.period = opts.period;
    return ERR_OK;
}

// uri_parse reads an otpauth URI. A fault leaves the buffer as it was.
fn uri_parse(text: const u8[:], out: u8[>..]&) -> i64, UriParams {
    let base = out.len;
    let code, r = uri_parse_into(text, out);
    if code != ERR_OK { out.resize(base, 0); }
    return code, r;
}

// uri_parse_into does the work of uri_parse. It writes the texts of the result
// into the buffer of the caller and gives their places. The secret
// goes through the base32 reader of the encoding package, so a secret
// that is not base32 is a fault.
fn uri_parse_into(text: const u8[:], out: u8[>..]&) -> i64, UriParams {
    var r = UriParams { totp: true, name_at: 0, name_len: 0, issuer_at: 0, issuer_len: 0,
                        issuer_q_at: 0, issuer_q_len: 0, secret_at: 0, secret_len: 0,
                        algo_at: 0, algo_len: 0, digits: 0, period: 0, counter: -1 };
    let n = text.len;
    if n < 14 { return ERR_BAD_URI, r; }
    if text[..8] != "otpauth:" { return ERR_BAD_URI, r; }
    if text[8] != '/' || text[9] != '/' { return ERR_BAD_URI, r; }
    var at: i64 = 10;
    let has_totp = at + 4 <= n && text[at..at + 4] == "totp" && (at + 4 == n || text[at + 4] == '/');
    let has_hotp = at + 4 <= n && text[at..at + 4] == "hotp" && (at + 4 == n || text[at + 4] == '/');
    if has_totp { r.totp = true; at = at + 4; }
    else if has_hotp { r.totp = false; at = at + 4; }
    else { return ERR_BAD_URI, r; }
    if at >= n { return ERR_BAD_URI, r; }
    if text[at] != '/' { return ERR_BAD_URI, r; }
    at = at + 1;
    // The label ends at the question mark.
    var label_end = n;
    var q_at: i64 = -1;
    var i: i64 = at;
    while i < n {
        if text[i] == '?' { label_end = i; q_at = i + 1; i = n; }
        i = i + 1;
    }
    // The label splits on the colon before the parts decode.
    var colon: i64 = -1;
    i = at;
    while i < label_end {
        if text[i] == ':' { colon = i; i = label_end; }
        i = i + 1;
    }
    let base = out.len;
    r.name_at = base;
    if colon >= 0 {
        r.issuer_at = base;
        uri_unescape(out, text[at..colon]);
        r.issuer_len = out.len - base;
        r.name_at = out.len;
        uri_unescape(out, text[colon + 1..label_end]);
    } else {
        uri_unescape(out, text[at..label_end]);
    }
    r.name_len = out.len - r.name_at;
    // The query holds the parameters.
    var counter_seen = false;
    // A key that stands twice is a fault. pyotp lets the last one win.
    var seen: i64 = 0;
    if q_at >= 0 {
        var seg: u8[>..] = [];
        i = q_at;
        while i <= n {
            if i == n || text[i] == '&' {
                if seg.len > 0 {
                    var eq: i64 = -1;
                    var j: i64 = 0;
                    while j < seg.len {
                        if seg[j] == '=' { eq = j; j = seg.len; }
                        j = j + 1;
                    }
                    var key: u8[>..] = [];
                    var val: u8[>..] = [];
                    if eq >= 0 {
                        uri_unescape(key, seg[..eq]);
                        uri_unescape(val, seg[eq + 1..]);
                    } else {
                        uri_unescape(key, seg[..]);
                    }
                    if key == "secret" {
                        if seen & 1 != 0 { return ERR_BAD_URI, r; }
                        seen = seen | 1;
                        r.secret_at = out.len;
                        uri_unescape(out, val[..]);
                        r.secret_len = out.len - r.secret_at;
                    } else if key == "issuer" {
                        if seen & 2 != 0 { return ERR_BAD_URI, r; }
                        seen = seen | 2;
                        r.issuer_q_at = out.len;
                        uri_unescape(out, val[..]);
                        r.issuer_q_len = out.len - r.issuer_q_at;
                    } else if key == "algorithm" {
                        if seen & 4 != 0 { return ERR_BAD_URI, r; }
                        seen = seen | 4;
                        r.algo_at = out.len;
                        uri_unescape(out, val[..]);
                        r.algo_len = out.len - r.algo_at;
                    } else if key == "digits" {
                        if seen & 8 != 0 { return ERR_BAD_URI, r; }
                        seen = seen | 8;
                        r.digits = number_of(val);
                        if r.digits < 6 || r.digits > 9 { return ERR_BAD_URI, r; }
                    } else if key == "period" {
                        if seen & 16 != 0 { return ERR_BAD_URI, r; }
                        seen = seen | 16;
                        r.period = number_of(val);
                        if r.period < 1 { return ERR_BAD_URI, r; }
                    } else if key == "counter" {
                        if seen & 32 != 0 { return ERR_BAD_URI, r; }
                        seen = seen | 32;
                        r.counter = number_of(val);
                        if r.counter < 0 { return ERR_BAD_URI, r; }
                        counter_seen = true;
                    } else {
                        return ERR_BAD_URI, r;
                    }
                }
                seg.resize(0, 0);
            } else {
                seg.push(text[i]);
            }
            i = i + 1;
        }
    }
    if r.secret_len == 0 { return ERR_BAD_URI, r; }
    if !secret_ok(out[r.secret_at..r.secret_at + r.secret_len]) { return ERR_BAD_URI, r; }
    if r.algo_len > 0 && algo_from_name(out[r.algo_at..r.algo_at + r.algo_len]) < 0 {
        return ERR_BAD_URI, r;
    }
    // The issuer of the label and the issuer of the query must match.
    if r.issuer_len > 0 && r.issuer_q_len > 0 {
        let lab = out[r.issuer_at..r.issuer_at + r.issuer_len];
        let qis = out[r.issuer_q_at..r.issuer_q_at + r.issuer_q_len];
        if lab != qis { return ERR_BAD_URI, r; }
    }
    // The type and the counter belong together.
    if r.totp && counter_seen { return ERR_BAD_URI, r; }
    if !r.totp && !counter_seen { return ERR_BAD_URI, r; }
    return ERR_OK, r;
}

// no_pad_options gives the options that read the text an app shows.
fn no_pad_options() -> encoding::Options {
    var opts = encoding::text_options();
    opts.padding = false;
    return opts;
}

// secret_ok tells whether the text is a base32 secret. The base32
// reader of the encoding package decides, so the URI never holds a text
// that the reader refuses: no space, no byte after the padding, no
// leftover bits.
fn secret_ok(text: const u8[:]) -> bool {
    if text.len == 0 { return false; }
    var opts = encoding::strict_options();
    opts.padding = false;
    var scratch: u8[>..] = [];
    let code, pos = encoding::base32_decode(scratch, text, opts);
    return code == encoding::ERR_OK;
}
