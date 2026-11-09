// A QR code for the key URI, printed as text and written as a PNG size.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import encoding from "rekanalar/goose-encoding@v1.0.0";
import otp from "..";

fn main() {
    var uri: u8[>..] = [];
    let fault = otp::uri_build(uri, "JBSWY3DPEHPK3PXP", "Example", "alice@example.com", 0, false,
                               otp::default_params());
    assert(fault == otp::ERR_OK);
    var modules: u8[>..] = [];
    let code, size = otp::qr_encode(modules, uri[..]);
    assert(code == otp::ERR_OK);
    // Two modules per text row: the upper and the lower half block.
    var y: i64 = -2;
    while y < size + 2 {
        var line: u8[>..] = [];
        var x: i64 = -2;
        while x < size + 2 {
            var top = false;
            var low = false;
            if x >= 0 && x < size && y >= 0 && y < size { top = modules[y * size + x] == 1; }
            if x >= 0 && x < size && y + 1 >= 0 && y + 1 < size { low = modules[(y + 1) * size + x] == 1; }
            if top && low { for c in "█" { line.push(c); } }
            else if top { for c in "▀" { line.push(c); } }
            else if low { for c in "▄" { line.push(c); } }
            else { line.push(' '); }
            x = x + 1;
        }
        print(line[..], "\n");
        y = y + 2;
    }
    var png: u8[>..] = [];
    assert(otp::qr_png(png, uri[..], 4) == otp::ERR_OK);
    print("png     : ", png.len, " bytes\n");
}
