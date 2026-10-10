package seal

// Byte-exact vectors for pw = 32 x 0x11, code "12345678", context {gitlab.corp.example, login, 1}.
//
// They were computed by an independent implementation of the documented steps (Python's hashlib.pbkdf2_hmac and a
// hand-written HKDF over hmac), not copied from this package's output, and they agree with it bit for bit. The
// browser test asserts the same three values from WebCrypto, so Go, Python and the browser all derive the same keys.
// They are exported only so that the page's tests can use the same numbers.
const (
	VectorStretched = "030a1cf8549879b43fe463afcd69ddb513747665f0e9e74a49a0382a8b9e4981"
	VectorPlainKey  = "f3686ee82162c77be03ff46b38115673bc9e42e3b8931f5aba01bda84ea08f79"
	VectorKey       = "c29e9ce049c4e964ac02653a51c3bceaaddafa64690555b06dd5b046c3fdac10"
)

// Vectors for the link layer: code "12345678", context {fingerprint "AB" x 20, login, 1}. Computed by the same
// independent Python implementation (hashlib.pbkdf2_hmac, hand-written HKDF).
const (
	VectorLinkStretched = "309fd754c8d2f77598ac7e274b122ee53ef64e630d279fdcb3175e53b4c77ee5"
	VectorLinkSlotKey   = "5be9bc5e3f81f50588cbc0a322c203c44d561cd8bf8ad9675c09dd3ca18d51a7"
)
