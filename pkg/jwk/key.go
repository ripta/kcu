package jwk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/pkg/errors"
)

// Key is a JSON web key.
type Key struct {
	KeyType string `json:"kty,omitempty"`

	ParameterN string `json:"n,omitempty"`
	ParameterE string `json:"e,omitempty"`
	ParameterD string `json:"d,omitempty"`

	ParameterP string `json:"p,omitempty"`
	ParameterQ string `json:"q,omitempty"`

	ParameterDP string `json:"dp,omitempty"`
	ParameterDQ string `json:"dq,omitempty"`
	ParameterQI string `json:"qi,omitempty"`
}

// Modulus is the modulus component.
func (k Key) Modulus() (*big.Int, error) {
	return base64URLToBigInt(k.ParameterN)
}

// PrivateExponent is the private exponent component.
func (k Key) PrivateExponent() (*big.Int, error) {
	return base64URLToBigInt(k.ParameterD)
}

// PublicExponent is the public exponent component.
func (k Key) PublicExponent() (*big.Int, error) {
	return base64URLToBigInt(k.ParameterE)
}

// RSAPrivateKey builds an RSA private key PEM block.
func (k Key) RSAPrivateKey() (*pem.Block, error) {
	pn, err := base64URLToBigInt(k.ParameterN)
	if err != nil {
		return nil, errors.Wrap(err, "decoding key modulus")
	}

	pe, err := base64URLToBigInt(k.ParameterE)
	if err != nil {
		return nil, errors.Wrap(err, "decoding key public exponent")
	}

	pd, err := base64URLToBigInt(k.ParameterD)
	if err != nil {
		return nil, errors.Wrap(err, "decoding key private exponent")
	}

	pp, err := base64URLToBigInt(k.ParameterP)
	if err != nil {
		return nil, errors.Wrap(err, "decoding first prime")
	}

	pq, err := base64URLToBigInt(k.ParameterQ)
	if err != nil {
		return nil, errors.Wrap(err, "decoding second prime")
	}

	// pdp, _ := base64URLToBigInt(k.ParameterDP)
	// pdq, _ := base64URLToBigInt(k.ParameterDQ)
	// pqi, _ := base64URLToBigInt(k.ParameterQI)

	pvt := x509.MarshalPKCS1PrivateKey(&rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: pn,
			E: int(pe.Int64()),
		},
		D:      pd,
		Primes: []*big.Int{pp, pq},
	})

	bl := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pvt,
	}
	return &bl, nil
}

// RSAPublicKey builds an RSA public key PEM block.
func (k Key) RSAPublicKey() (*pem.Block, error) {
	pn, err := base64URLToBigInt(k.ParameterN)
	if err != nil {
		return nil, errors.Wrap(err, "decoding key modulus")
	}

	pe, err := base64URLToBigInt(k.ParameterE)
	if err != nil {
		return nil, errors.Wrap(err, "decoding key public exponent")
	}

	pub, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{
		N: pn,
		E: int(pe.Int64()),
	})
	if err != nil {
		return nil, errors.Wrap(err, "constructing public key")
	}

	bl := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pub,
	}
	return &bl, nil
}
