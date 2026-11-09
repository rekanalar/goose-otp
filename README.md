# goose-otp

[![ci](https://github.com/rekanalar/goose-otp/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-otp/actions/workflows/ci.yml)

One-time passwords for Goose. The package builds and checks the codes of HOTP (RFC 4226) and TOTP (RFC 6238).

## Install

```goose
import otp from "rekanalar/goose-otp@v0.1.0";
```

The package depends on `kaitk/goose-hash@v0.0.4` for SHA-1, SHA-256 and the random source. It depends on `rekanalar/goose-encoding@v1.0.0` for base32. Declare both imports in the root file of your program.

## Reference libraries

| Library | What the package matches |
|---|---|
| Python `pyotp` | `HOTP.at`, `TOTP.at`, `verify` with a window, `random_base32` |
| Go `pquerna/otp` | SHA-1, SHA-256 and SHA-512, 6 to 8 digits, `ValidateCustom` |
| Rust `totp-rs` | The minimum length of a secret, the check with a skew |
| Node `otplib` | `window` and the delta of the match |

## Features

- **HOTP and TOTP.** The code for a counter or for a time.
- **SHA-1, SHA-256 and SHA-512.** The package holds its own SHA-512, because `goose-hash` has none.
- **6 to 9 digits.** Leading zeros stay.
- **Verify with a window.** The call gives the counter that matched. The caller stores it and refuses a reuse.
- **Base32 secrets.** The package reads the text that an app shows: either case, with spaces, with no padding.
- **Random secrets.** The bytes come from the random source of the operating system.

## API

| Call | What it does |
|---|---|
| `default_params()` | The rules of most apps: SHA-1, 6 digits, 30 seconds |
| `hotp(out, secret, counter, p)` | Adds the text of the code to `out`. Gives a code |
| `totp(out, secret, now, p)` | The same for a time in seconds since 1970 |
| `hotp_value`, `totp_counter` | The number of a code, and the step of a time |
| `hotp_verify(secret, code, counter, ahead, p)` | Gives the counter that matched, and a code |
| `totp_verify(secret, code, now, back, ahead, p)` | Gives the step that matched, and a code |
| `secret_decode(out, text)` | Adds the bytes of a base32 secret to `out` |
| `secret_encode(out, secret)` | Adds the base32 text of a secret to `out` |
| `random_secret(out, n)` | Adds `n` random bytes to `out` |
| `error_text(code)` | Names a code |

### The rules

| Field | Meaning | Default |
|---|---|---|
| `algo` | `ALGO_SHA1`, `ALGO_SHA256` or `ALGO_SHA512` | `ALGO_SHA1` |
| `digits` | The count of digits, 6 to 9 | 6 |
| `period` | The seconds of one TOTP step | 30 |
| `t0` | The time of step 0, in seconds since 1970 | 0 |
| `min_secret` | The shortest secret in bytes | 16 |

### The codes

| Code | The fault |
|---|---|
| `ERR_OK` | No fault |
| `ERR_BAD_DIGITS` | The count of digits is not from 6 to 9 |
| `ERR_BAD_ALGORITHM` | The hash function is not known |
| `ERR_BAD_PERIOD` | The period is less than 1 |
| `ERR_SHORT_SECRET` | The secret is empty or shorter than `min_secret` |
| `ERR_BAD_COUNTER` | The counter or the time is negative, or before `t0` |
| `ERR_BAD_CODE` | The code has not `digits` digits, or holds a byte that is not a digit |
| `ERR_NO_MATCH` | No counter in the window gives the code |
| `ERR_BAD_SECRET_TEXT` | The base32 text of a secret is not valid |
| `ERR_BAD_WINDOW` | A window is negative or larger than `MAX_WINDOW` (1000) |
| `ERR_BAD_LENGTH` | `random_secret` got a length that is not from 1 to `MAX_SECRET` (1024) |

A call that fails leaves the buffer of the caller as it was.

## Example

```goose
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import encoding from "rekanalar/goose-encoding@v1.0.0";
import otp from "rekanalar/goose-otp@v0.1.0";

fn main() {
    var secret: u8[>..] = [];
    assert(otp::secret_decode(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") == otp::ERR_OK);
    var code: u8[>..] = [];
    assert(otp::totp(code, secret[..], 59, otp::default_params()) == otp::ERR_OK);
    print(code[..], "\n");
}
```

## Security

- **The check takes the same time for every code.** The verify call tests every counter of the window. It compares the code with no early exit.
- **A weak secret is a fault.** RFC 4226 asks for 128 bits at least. The package refuses a secret of fewer than 16 bytes unless the caller lowers `min_secret`. The Python library `pyotp` takes any secret.
- **The window has a limit.** A window larger than 1000 steps is a fault. A large window gives an attacker more codes to guess with.
- **The code needs digits.** The verify call refuses a code of the wrong length. It refuses a byte that is not a digit. Both checks run before any hash.
- **The secret comes from the operating system.** `random_secret` reads the random source of the operating system. It never uses a seeded generator.
- **The secret text is strict.** The base32 reader refuses a byte that is not in the alphabet and leftover bits. It does not skip a bad byte.

Risks that stay: the package cannot stop a caller from trying many codes.

**Rate-limit the verify call** in your program. A 6 digit code has one million values. Store the step or counter that matched. Refuse a step that is not larger. The package keeps no state and stores no secret. Your program stores the secrets safely.

## Limits

- **No `otpauth://` URI.** `pyotp` and `totp-rs` build and parse the URI of the Google Authenticator format. The package does not.
- **No Steam codes.** `pyotp` and `totp-rs` hold a Steam variant. The package does not.
- **No MD5.** `pquerna/otp` takes MD5. The package refuses it. MD5 is broken and no app needs it.
- **Digits from 6 to 9.** `pyotp` takes any count. Go `pquerna/otp` takes 6, 7 and 8. A 31 bit value holds 10 digits with a bias, so the package stops at 9.
- **A counter is a signed 64 bit number.** RFC 4226 holds an unsigned 64 bit counter. A counter of 2 to the power of 63 or more is not possible.
- **The random source ends the program.** `random_secret` reads the random source of the operating system. If that source fails, the program ends. It never returns weak bytes.
- **The package holds no clock.** The caller gives the time in seconds.
- **SHA-512 is not in `goose-hash`.** The package holds its own pure Goose code. It runs on the Goose rounds only, with no CPU instructions. It is slower than a library on the CPU instructions. A code needs three or four hash calls, so the cost is small.
- **The package builds a C file of `goose-hash`.** `goose run` builds it once on first use.
