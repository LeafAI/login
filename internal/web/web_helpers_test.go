package web_test

import "encoding/base64"

func browsertestB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
