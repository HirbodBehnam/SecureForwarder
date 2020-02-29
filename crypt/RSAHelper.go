package crypt

// From https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a
// Editor https://github.com/miguelmota

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"log"
)

func RSAGenerateKeyPair(bits int) *rsa.PrivateKey {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	return privkey
}

// PublicKeyToBytes public key to bytes
func RSAPublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes
}

// BytesToPublicKey bytes to public key
func RSABytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

// EncryptWithPublicKey encrypts data with public key
func RSAEncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with private key
func RSADecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
