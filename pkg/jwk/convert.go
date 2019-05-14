package jwk

import (
	"encoding/base64"
	"math/big"

	"github.com/pkg/errors"
)

// base64URLToBigInt decodes string "s" into bytes, and interprets it as bytes
// of a big-endian unsigned int.
func base64URLToBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "base64-URL decode")
	}

	return new(big.Int).SetBytes(b), nil
}
