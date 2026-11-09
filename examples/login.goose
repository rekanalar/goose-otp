// A login that checks a time based code and refuses a reuse.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import encoding from "rekanalar/goose-encoding@v1.0.0";
import otp from "..";

fn main() {
    // The secret of the user, as the app shows it.
    var secret: u8[>..] = [];
    assert(otp::secret_decode(secret, "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ") == otp::ERR_OK);

    // The server builds the code for a time, here the time of RFC 6238.
    var p = otp::default_params();
    p.digits = 8;
    var code: u8[>..] = [];
    assert(otp::totp(code, secret[..], 59, p) == otp::ERR_OK);
    print("code    : ", code[..], "\n");

    // The user sends the code 20 seconds later. One step of slack back.
    // The server stores the step that matched. A step that is not larger
    // than the stored one is a reuse.
    var last_step: i64 = 0;
    let step, fault = otp::totp_verify(secret[..], code[..], 79, 1, 0, p);
    print("verify  : ", otp::error_text(fault), " at step ", step, "\n");
    if fault == otp::ERR_OK && step > last_step {
        last_step = step;
    }
    let again, fault2 = otp::totp_verify(secret[..], code[..], 80, 1, 0, p);
    if fault2 == otp::ERR_OK && again <= last_step {
        print("reuse   : refused\n");
    }

    // A new secret from the random source, shown as base32.
    var fresh: u8[>..] = [];
    assert(otp::random_secret(fresh, 20) == otp::ERR_OK);
    var shown: u8[>..] = [];
    otp::secret_encode(shown, fresh[..]);
    print("new key : ", shown.len, " characters\n");
}
