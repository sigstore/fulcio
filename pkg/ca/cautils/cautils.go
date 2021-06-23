package cautils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

func CheckSignature(pub crypto.PublicKey, proof []byte, email string) error {
	h := sha256.Sum256([]byte(email))

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ok := ecdsa.VerifyASN1(k, h[:], proof); !ok {
			return errors.New("signature could not be verified")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], proof); err != nil {
			return fmt.Errorf("signature could not be verified: %v", err)
		}
	}

	return nil
}
