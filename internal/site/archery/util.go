package archery

import (
	"encoding/json"
	"errors"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func asAPIError(err error, target **APIError) bool { return errors.As(err, target) }
