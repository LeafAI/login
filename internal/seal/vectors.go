package seal

// Byte-exact vectors for pw = 32 x 0x11, code "12345678", context {gitlab.corp.example, login, 1}.
//
// They were computed by an independent implementation of the documented steps (Python's hashlib.pbkdf2_hmac and a
// hand-written HKDF over hmac), not copied from this package's output, and they agree with it bit for bit. The
// browser test asserts the same three values from WebCrypto, so Go, Python and the browser all derive the same keys.
// They are exported only so that the page's tests can use the same numbers.
const (
	VectorStretched = "030a1cf8549879b43fe463afcd69ddb513747665f0e9e74a49a0382a8b9e4981"
	VectorPlainKey  = "4a019600ad637419cc6fc22be003861a1c3d8950000bc7dbd2e99f9324abfd58"
	VectorKey       = "7c7f82307a84d834822413bfea3a4888858fd0a81f0d4039e361f48d23989e06"
)

// Vectors for the link layer: code "12345678", context {fingerprint "AB" x 20, login, 1}. Computed by the same
// independent Python implementation (hashlib.pbkdf2_hmac, hand-written HKDF).
const (
	VectorLinkStretched = "87bcd3fda20251f55d5c8e2cba1b0824fe610e0f97287163264fc10f1cad73e7"
	VectorLinkSlotKey   = "b9bb5b99b57271e8e4acc9d4e1e14cef574072ef9e95adcd63592ca380ca2d16"
)
