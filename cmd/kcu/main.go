package main

import (
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

	"github.com/pkg/errors"

	"github.com/ripta/kcu/pkg/jwk"
)

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "reading from stdin")
	}

	var k jwk.Key
	if err := json.Unmarshal(in, &k); err != nil {
		return errors.Wrap(err, "unmarshaling key")
	}

	pub, err := k.RSAPublicKey()
	if err != nil {
		return errors.Wrap(err, "public key")
	}

	if err := pem.Encode(os.Stdout, pub); err != nil {
		return errors.Wrap(err, "printing out public key")
	}

	pvt, err := k.RSAPrivateKey()
	if err != nil {
		return errors.Wrap(err, "private key")
	}

	if err := pem.Encode(os.Stdout, pvt); err != nil {
		return errors.Wrap(err, "printing out private key")
	}

	return nil
}
