// Tests for the otp package. Run with: goose run test/run.goose
//
// The tests hold the vectors of RFC 4226 appendix D and RFC 6238
// appendix B. They also hold the codes that the Python modules hmac and
// hashlib give for keys longer than a block.

import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import encoding from "rekanalar/goose-encoding@v1.0.0";
import otp from "..";

fn params(algo: i64, digits: i64) -> otp::Params {
    var p = otp::default_params();
    p.algo = algo;
    p.digits = digits;
    return p;
}

// hotp_is checks the text of one code.
fn hotp_is(secret: const u8[:], counter: i64, p: otp::Params, want: const u8[:]) {
    var out: u8[>..] = [];
    let code = otp::hotp(out, secret, counter, p);
    assert(code == otp::ERR_OK);
    assert(out == want);
}

fn totp_is(secret: const u8[:], now: i64, p: otp::Params, want: const u8[:]) {
    var out: u8[>..] = [];
    let code = otp::totp(out, secret, now, p);
    assert(code == otp::ERR_OK);
    assert(out == want);
}

fn test_rfc4226() {
    let s = "12345678901234567890";
    let want: const u8[:][10] = ["755224", "287082", "359152", "969429", "338314",
                                  "254676", "287922", "162583", "399871", "520489"];
    var i: i64 = 0;
    while i < 10 {
        hotp_is(s, i, otp::default_params(), want[i]);
        i = i + 1;
    }
}

fn test_rfc6238() {
    let k1 = "12345678901234567890";
    let k256 = "12345678901234567890123456789012";
    let k512 = "1234567890123456789012345678901234567890123456789012345678901234";
    let times: i64[6] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
    let w1: const u8[:][6] = ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"];
    let w2: const u8[:][6] = ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"];
    let w5: const u8[:][6] = ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"];
    var i: i64 = 0;
    while i < 6 {
        totp_is(k1, times[i], params(otp::ALGO_SHA1, 8), w1[i]);
        totp_is(k256, times[i], params(otp::ALGO_SHA256, 8), w2[i]);
        totp_is(k512, times[i], params(otp::ALGO_SHA512, 8), w5[i]);
        i = i + 1;
    }
}

fn long_key(n: i64) -> u8[>..] {
    var k: u8[>..] = [];
    var i: i64 = 0;
    while i < n { k.push(((i * 7 + 3) % 256) as u8); i = i + 1; }
    return k;
}

fn test_long_keys() {
    // Python: hmac with a key of 130 bytes, counter 1, 6 digits.
    let k = long_key(130);
    hotp_is(k[..], 1, params(otp::ALGO_SHA1, 6), "279925");
    hotp_is(k[..], 1, params(otp::ALGO_SHA256, 6), "090166");
    hotp_is(k[..], 1, params(otp::ALGO_SHA512, 6), "582073");
    let k2 = long_key(100);
    hotp_is(k2[..], 5, params(otp::ALGO_SHA1, 7), "3832597");
    // A counter above 32 bits, 9 digits, a key of 16 bytes.
    var k3: u8[>..] = [];
    var j: i64 = 0;
    while j < 16 { k3.push(j as u8); j = j + 1; }
    let big = 1099511627776 + 7;
    hotp_is(k3[..], big, params(otp::ALGO_SHA1, 9), "414440044");
    hotp_is(k3[..], big, params(otp::ALGO_SHA256, 9), "838838235");
    hotp_is(k3[..], big, params(otp::ALGO_SHA512, 9), "417132810");
}

fn sha512_prefix(n: i64) -> u8[>..] {
    let d = otp::digest(otp::ALGO_SHA512, long_bytes(n)[..]);
    var o: u8[>..] = [];
    var opts = encoding::strict_options();
    opts.lower = true;
    encoding::hex_encode(o, d[..8], opts);
    return o;
}

fn long_bytes(n: i64) -> u8[>..] {
    var k: u8[>..] = [];
    var i: i64 = 0;
    while i < n { k.push((i % 256) as u8); i = i + 1; }
    return k;
}

fn test_sha512_lengths() {
    // The lengths that stand at the edge of the padding.
    assert(sha512_prefix(0) == "cf83e1357eefb8bd");
    assert(sha512_prefix(1) == "b8244d028981d693");
    assert(sha512_prefix(111) == "a1a111449b198d9b");
    assert(sha512_prefix(112) == "c5fbd731d19d2ae1");
    assert(sha512_prefix(127) == "eab89674feaa34e2");
    assert(sha512_prefix(128) == "1dffd5e3adb71d45");
    assert(sha512_prefix(129) == "1d9da57fbbdab09a");
    assert(sha512_prefix(239) == "cb4c7fd522756d57");
    assert(sha512_prefix(240) == "6c48466c9f6c07e4");
}

fn test_faults() {
    let s = "12345678901234567890";
    var out: u8[>..] = [7];
    var p = otp::default_params();
    p.digits = 5;
    assert(otp::hotp(out, s, 0, p) == otp::ERR_BAD_DIGITS);
    p.digits = 10;
    assert(otp::hotp(out, s, 0, p) == otp::ERR_BAD_DIGITS);
    p = otp::default_params();
    p.algo = 3;
    assert(otp::hotp(out, s, 0, p) == otp::ERR_BAD_ALGORITHM);
    p = otp::default_params();
    p.period = 0;
    assert(otp::totp(out, s, 100, p) == otp::ERR_BAD_PERIOD);
    p = otp::default_params();
    assert(otp::hotp(out, "short", 0, p) == otp::ERR_SHORT_SECRET);
    assert(otp::hotp(out, "", 0, p) == otp::ERR_SHORT_SECRET);
    p.min_secret = 1;
    assert(otp::hotp(out, "", 0, p) == otp::ERR_SHORT_SECRET);
    assert(otp::hotp(out, "short", 0, p) == otp::ERR_OK);
    out.resize(1, 7);
    p = otp::default_params();
    assert(otp::hotp(out, s, -1, p) == otp::ERR_BAD_COUNTER);
    assert(otp::totp(out, s, -5, p) == otp::ERR_BAD_COUNTER);
    // A fault leaves the buffer as it was.
    assert(out.len == 1 && out[0] == 7);
    p.t0 = 100;
    assert(otp::totp(out, s, 99, p) == otp::ERR_BAD_COUNTER);
    assert(out.len == 1);
}

fn test_verify() {
    let s = "12345678901234567890";
    let p = otp::default_params();
    // The code of counter 3 is 969429. Counter 1 with 2 ahead finds it.
    let c, f = otp::hotp_verify(s, "969429", 1, 2, p);
    assert(f == otp::ERR_OK && c == 3);
    let c2, f2 = otp::hotp_verify(s, "969429", 1, 1, p);
    assert(f2 == otp::ERR_NO_MATCH);
    let c3, f3 = otp::hotp_verify(s, "96942", 1, 2, p);
    assert(f3 == otp::ERR_BAD_CODE);
    let c4, f4 = otp::hotp_verify(s, "96942a", 1, 2, p);
    assert(f4 == otp::ERR_BAD_CODE);
    let c5, f5 = otp::hotp_verify(s, "969429", 1, -1, p);
    assert(f5 == otp::ERR_BAD_WINDOW);
    let c6, f6 = otp::hotp_verify(s, "969429", 1, otp::MAX_WINDOW + 1, p);
    assert(f6 == otp::ERR_BAD_WINDOW);
    // TOTP: 59 s is step 1 and holds 94287082. The step before is 0.
    let p8 = params(otp::ALGO_SHA1, 8);
    let t, tf = otp::totp_verify(s, "94287082", 59, 0, 0, p8);
    assert(tf == otp::ERR_OK && t == 1);
    // A code of the step before the time, with a window of one step.
    let t2, tf2 = otp::totp_verify(s, "94287082", 89, 1, 0, p8);
    assert(tf2 == otp::ERR_OK && t2 == 1);
    let t3, tf3 = otp::totp_verify(s, "94287082", 89, 0, 0, p8);
    assert(tf3 == otp::ERR_NO_MATCH);
    // The window never goes below step 0.
    let t4, tf4 = otp::totp_verify(s, "94287082", 5, 5, 0, p8);
    assert(tf4 == otp::ERR_NO_MATCH);
    // A code of the step after the time.
    let t5, tf5 = otp::totp_verify(s, "94287082", 29, 0, 1, p8);
    assert(tf5 == otp::ERR_OK && t5 == 1);
}

fn test_uri_escape() {
    var o: u8[>..] = [];
    otp::uri_escape(o, "ACME");
    assert(o == "ACME");
    o.resize(0, 0);
    otp::uri_escape(o, "We:rd & Co");
    assert(o == "We%3Ard%20%26%20Co");
    o.resize(0, 0);
    otp::uri_escape(o, "a~b.c_d-e");
    assert(o == "a~b.c_d-e");
    o.resize(0, 0);
    var ctrl: u8[1] = [1];
    otp::uri_escape(o, ctrl[..]);
    assert(o == "%01");
}

fn test_uri_algo_name() {
    assert(otp::algo_from_name("SHA1") == otp::ALGO_SHA1);
    assert(otp::algo_from_name("sha256") == otp::ALGO_SHA256);
    assert(otp::algo_from_name("Sha512") == otp::ALGO_SHA512);
    assert(otp::algo_from_name("MD5") == -1);
    assert(otp::algo_from_name("SHA") == -1);
    assert(otp::algo_from_name("SHA1234567") == -1);
}

fn test_uri_build() {
    var o: u8[>..] = [];
    // pyotp: build_uri("JBSWY3DPEHPK3PXP","alice@example.com",issuer="ACME")
    let c1 = otp::uri_build(o, "JBSWY3DPEHPK3PXP", "ACME", "alice@example.com", 0, false, otp::default_params());
    assert(c1 == otp::ERR_OK);
    assert(o == "otpauth://totp/ACME:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME");
    // Only non-default parameters stand.
    o.resize(0, 0);
    var p = otp::default_params();
    p.algo = otp::ALGO_SHA256;
    p.digits = 8;
    p.period = 60;
    assert(otp::uri_build(o, "JBSWY3DPEHPK3PXP", "ACME", "u", 0, false, p) == otp::ERR_OK);
    assert(o == "otpauth://totp/ACME:u?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60");
    // HOTP holds the counter and no period.
    o.resize(0, 0);
    assert(otp::uri_build(o, "JBSWY3DPEHPK3PXP", "", "u", 7, true, p) == otp::ERR_OK);
    assert(o == "otpauth://hotp/u?secret=JBSWY3DPEHPK3PXP&counter=7&algorithm=SHA256&digits=8");
    // A label with no issuer.
    o.resize(0, 0);
    assert(otp::uri_build(o, "JBSWY3DPEHPK3PXP", "", "u", 0, false, otp::default_params()) == otp::ERR_OK);
    assert(o == "otpauth://totp/u?secret=JBSWY3DPEHPK3PXP");
    // No label at all is a fault.
    o.resize(0, 0);
    assert(otp::uri_build(o, "JBSWY3DPEHPK3PXP", "", "", 0, false, otp::default_params()) == otp::ERR_NO_ISSUER);
    assert(o.len == 0);
    // A secret that is not base32 is a fault.
    assert(otp::uri_build(o, "AB1!", "A", "u", 0, false, otp::default_params()) == otp::ERR_BAD_URI);
    // An empty secret is a fault.
    assert(otp::uri_build(o, "", "A", "u", 0, false, otp::default_params()) == otp::ERR_SHORT_SECRET);
}

fn test_uri_parse() {
    var raw: u8[>..] = [];
    // The text that pyotp builds reads back.
    let c1, r1 = otp::uri_parse("otpauth://totp/ACME:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME", raw);
    assert(c1 == otp::ERR_OK && r1.totp);
    assert(raw[r1.name_at..r1.name_at + r1.name_len] == "alice@example.com");
    assert(raw[r1.issuer_at..r1.issuer_at + r1.issuer_len] == "ACME");
    assert(raw[r1.secret_at..r1.secret_at + r1.secret_len] == "JBSWY3DPEHPK3PXP");
    // An encoded colon in the name stays one name.
    var raw2: u8[>..] = [];
    let c2, r2 = otp::uri_parse("otpauth://totp/We%3Ard%20%26%20Co:a%3Ab?secret=JBSWY3DPEHPK3PXP&issuer=We%3Ard%20%26%20Co", raw2);
    assert(c2 == otp::ERR_OK);
    assert(raw2[r2.name_at..r2.name_at + r2.name_len] == "a:b");
    assert(raw2[r2.issuer_at..r2.issuer_at + r2.issuer_len] == "We:rd & Co");
    // HOTP holds the counter.
    var raw3: u8[>..] = [];
    let c3, r3 = otp::uri_parse("otpauth://hotp/X:u?secret=JBSWY3DPEHPK3PXP&issuer=X&counter=7", raw3);
    assert(c3 == otp::ERR_OK && !r3.totp && r3.counter == 7);
    // The parameters land in the rules.
    var raw4: u8[>..] = [];
    let c4, r4 = otp::uri_parse("otpauth://totp/u?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=60", raw4);
    assert(c4 == otp::ERR_OK && r4.digits == 8 && r4.period == 60);
    assert(raw4[r4.algo_at..r4.algo_at + r4.algo_len] == "sha256");
    // The faults of pyotp.
    var keep: u8[>..] = [1];
    let e1, _ = otp::uri_parse("https://totp/u?secret=X", keep);
    assert(e1 == otp::ERR_BAD_URI && keep.len == 1);
    let e2, _ = otp::uri_parse("otpauth://foo/u?secret=X", keep);
    assert(e2 == otp::ERR_BAD_URI);
    let e3, _ = otp::uri_parse("otpauth://totp/u", keep);
    assert(e3 == otp::ERR_BAD_URI);
    let e4, _ = otp::uri_parse("otpauth://totp/u?secret=MB&algorithm=MD5", keep);
    assert(e4 == otp::ERR_BAD_URI);
    let e5, _ = otp::uri_parse("otpauth://totp/u?secret=MB&digits=5", keep);
    assert(e5 == otp::ERR_BAD_URI);
    let e6, _ = otp::uri_parse("otpauth://totp/u?secret=MB&issuer=L&issuer=M", keep);
    assert(e6 == otp::ERR_BAD_URI);
    // An issuer that differs between label and query.
    let e7, _ = otp::uri_parse("otpauth://totp/L:u?secret=MB&issuer=M", keep);
    assert(e7 == otp::ERR_BAD_URI);
    // An unknown key.
    let e8, _ = otp::uri_parse("otpauth://totp/u?secret=MB&image=https://x/y.png", keep);
    assert(e8 == otp::ERR_BAD_URI);
    // A counter on totp, and no counter on hotp.
    let e9, _ = otp::uri_parse("otpauth://totp/u?secret=MB&counter=1", keep);
    assert(e9 == otp::ERR_BAD_URI);
    let e10, _ = otp::uri_parse("otpauth://hotp/u?secret=MB", keep);
    assert(e10 == otp::ERR_BAD_URI);
    // A period of zero.
    let e11, _ = otp::uri_parse("otpauth://totp/u?secret=MB&period=0", keep);
    assert(e11 == otp::ERR_BAD_URI);
    // A bad base32 secret.
    let e12, _ = otp::uri_parse("otpauth://totp/u?secret=AB1!", keep);
    assert(e12 == otp::ERR_BAD_URI);
}

fn test_uri_hostile() {
    var o: u8[>..] = [];
    let p = otp::default_params();
    // A secret cannot carry a parameter or a space.
    assert(otp::uri_build(o, "AAAA=&issuer=EVIL", "", "u", 0, false, p) == otp::ERR_BAD_URI);
    assert(otp::uri_build(o, "A A A A", "", "u", 0, false, p) == otp::ERR_BAD_URI);
    assert(otp::uri_build(o, "AB", "", "u", 0, false, p) == otp::ERR_BAD_URI);
    assert(o.len == 0);
    var keep: u8[>..] = [1];
    let a1, _ = otp::uri_parse("otpauth://totp/u?secret=AAAA=!!", keep);
    assert(a1 == otp::ERR_BAD_URI);
    let a2, _ = otp::uri_parse("otpauth://totp/u?secret=AAAA=AAAA", keep);
    assert(a2 == otp::ERR_BAD_URI);
    let a3, _ = otp::uri_parse("otpauth://totp/u?secret=AB%20CD", keep);
    assert(a3 == otp::ERR_BAD_URI);
    let a4, _ = otp::uri_parse("otpauth://totp/u?secret=AB", keep);
    assert(a4 == otp::ERR_BAD_URI);
    // A late fault leaves the buffer as it was.
    let a5, _ = otp::uri_parse("otpauth://totp/L:u?secret=MB&digits=5", keep);
    assert(a5 == otp::ERR_BAD_URI && keep.len == 1 && keep[0] == 1);
    // The largest numbers never crash the build.
    var big = p;
    big.period = 9223372036854775807;
    assert(otp::uri_build(o, "JBSWY3DPEHPK3PXP", "ACME", "u", 0, false, big) == otp::ERR_OK);
    var o2: u8[>..] = [];
    assert(otp::uri_build(o2, "JBSWY3DPEHPK3PXP", "", "u", 9223372036854775807, true, p) == otp::ERR_OK);
}

fn test_uri_round_trip() {
    // Build with the rules, read back, and build the code from the rules.
    var p = otp::default_params();
    p.algo = otp::ALGO_SHA512;
    p.digits = 7;
    p.period = 90;
    var uri: u8[>..] = [];
    let s = "12345678901234567890";
    var text: u8[>..] = [];
    otp::secret_encode(text, s);
    assert(otp::uri_build(uri, text[..], "Bank", "u@x", 0, false, p) == otp::ERR_OK);
    var raw: u8[>..] = [];
    let c, r = otp::uri_parse(uri[..], raw);
    assert(c == otp::ERR_OK);
    var q = otp::default_params();
    q.algo = otp::algo_from_name(raw[r.algo_at..r.algo_at + r.algo_len]);
    q.digits = r.digits;
    q.period = r.period;
    assert(q.algo == p.algo && q.digits == p.digits && q.period == p.period);
    // The secret text decodes to the secret.
    var secret: u8[>..] = [];
    var opts = encoding::text_options();
    opts.padding = false;
    assert(encoding::base32_decode(secret, raw[r.secret_at..r.secret_at + r.secret_len], opts) == encoding::ERR_OK);
    assert(secret == s);
}

fn test_overflow() {
    let s = "12345678901234567890";
    let p = otp::default_params();
    var out: u8[>..] = [7];
    // A time whose difference to t0 does not fit in an i64.
    var big = p;
    big.t0 = -9223372036854775807 - 1;
    assert(otp::totp(out, s, 9223372036854775807, big) == otp::ERR_BAD_COUNTER);
    assert(out.len == 1 && out[0] == 7);
    big.t0 = -1;
    assert(otp::totp(out, s, 9223372036854775807, big) == otp::ERR_BAD_COUNTER);
    // A counter at the largest number, with a window.
    let maxc = 9223372036854775807;
    var one: u8[>..] = [];
    assert(otp::hotp(one, s, maxc, p) == otp::ERR_OK);
    let c, f = otp::hotp_verify(s, one[..], maxc, 5, p);
    assert(f == otp::ERR_OK && c == maxc);
    let c2, f2 = otp::hotp_verify(s, one[..], maxc, 0, p);
    assert(f2 == otp::ERR_OK && c2 == maxc);
    // The time at the largest number, with a period of one.
    var q = p;
    q.period = 1;
    var code: u8[>..] = [];
    assert(otp::totp(code, s, maxc, q) == otp::ERR_OK);
    let c3, f3 = otp::totp_verify(s, code[..], maxc, 1, 1, q);
    assert(f3 == otp::ERR_OK && c3 == maxc);
}

fn test_secret_text() {
    var raw: u8[>..] = [];
    // The base32 text of 12345678901234567890, in lower case and with
    // spaces, as an app shows it.
    assert(otp::secret_decode(raw, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq") == otp::ERR_OK);
    assert(raw == "12345678901234567890");
    var back: u8[>..] = [];
    otp::secret_encode(back, raw[..]);
    assert(back == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    var keep: u8[>..] = [1];
    assert(otp::secret_decode(keep, "GEZ1!") == otp::ERR_BAD_SECRET_TEXT);
    assert(keep.len == 1);
    var r: u8[>..] = [];
    assert(otp::random_secret(r, 20) == otp::ERR_OK && r.len == 20);
    var r2: u8[>..] = [];
    assert(otp::random_secret(r2, 20) == otp::ERR_OK);
    assert(r != r2);
    assert(otp::random_secret(r, 0) == otp::ERR_BAD_LENGTH);
    assert(otp::random_secret(r, otp::MAX_SECRET + 1) == otp::ERR_BAD_LENGTH);
    assert(r.len == 20);
}

fn main() {
    test_rfc4226();
    test_rfc6238();
    test_long_keys();
    test_sha512_lengths();
    test_faults();
    test_verify();
    test_uri_escape();
    test_uri_algo_name();
    test_uri_build();
    test_uri_parse();
    test_uri_round_trip();
    test_uri_hostile();
    test_overflow();
    test_secret_text();
    print("all otp tests pass\n");
}
