// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

const namedCurveType = 3

//// hashForServerKeyExchange hashes the given slices and returns their digest
//// using the given hash function (for >= TLS 1.2) or using a default based on
//// the sigType (for earlier TLS versions).
//func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) ([]byte, error) {
//	if version >= VersionTLS12 {
//		h := hashFunc.New()
//		for _, slice := range slices {
//			h.Write(slice)
//		}
//		digest := h.Sum(nil)
//		return digest, nil
//	}
//	if sigType == signatureECDSA {
//		return sha1Hash(slices), nil
//	}
//	return md5SHA1Hash(slices), nil
//}
//
//func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
//	switch id {
//	case CurveP256:
//		return elliptic.P256(), true
//	case CurveP384:
//		return elliptic.P384(), true
//	case CurveP521:
//		return elliptic.P521(), true
//	default:
//		return nil, false
//	}
//
//}

// ecdheKeyAgreementGM implements a TLS key agreement where the server
// generates an ephemeral SM2 public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH.
type ecdheKeyAgreementGM struct {
	isServer      bool
	version       uint16
	curveid       CurveID
	encCert       *Certificate
	privateKey    *sm2.PrivateKey
	peerPublicKey *sm2.PublicKey
	peerCert      *x509.Certificate
}

func (ka *ecdheKeyAgreementGM) generateServerKeyExchange(config *Config, signCert, cipherCert *Certificate,
	clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	preferredCurves := config.curvePreferences()
NextCandidate:
	for _, candidate := range preferredCurves {
		for _, c := range clientHello.supportedCurves {
			if candidate == c {
				ka.curveid = c
				break NextCandidate
			}
		}
	}

	if ka.curveid == 0 {
		ka.curveid = 249
	}

	if ka.curveid != 249 {
		for _, c := range clientHello.supportedCurves {
			if c == 249 {
				ka.curveid = 249
			}
		}
	}

	var ecdhePublic []byte
	curve, ok := curveForCurveID(ka.curveid)

	if !ok {
		return nil, errors.New("tls: preferredCurves includes unsupported curve")
	}

	var err error
	ka.privateKey, err = sm2.GenerateKey(config.rand())
	if err != nil {
		return nil, err
	}
	ecdhePublic = elliptic.Marshal(curve, ka.privateKey.X, ka.privateKey.Y)

	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHParams[0] = namedCurveType
	serverECDHParams[1] = byte(ka.curveid >> 8)
	serverECDHParams[2] = byte(ka.curveid & 0xff)
	serverECDHParams[3] = byte(len(ecdhePublic))
	copy(serverECDHParams[4:], ecdhePublic)

	priv, ok := signCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}

	signatureAlgorithm, sigType, hashFunc, err := pickSignatureAlgorithm(priv.Public(), clientHello.supportedSignatureAlgorithms, supportedSignatureAlgorithms, ka.version)
	if err != nil {
		return nil, err
	}
	if sigType != signatureSM2 {
		return nil, errors.New("tls: certificate is not signed by sm2")
	}

	digest, err := hashForServerKeyExchange(sigType, hashFunc, ka.version, clientHello.random, hello.random, serverECDHParams)
	if err != nil {
		return nil, err
	}

	signOpts := crypto.SignerOpts(hashFunc)
	sig, err := priv.Sign(config.rand(), digest, signOpts)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHParams)
	k := skx.key[len(serverECDHParams):]
	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

func (ka *ecdheKeyAgreementGM) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) <= 4 {
		return nil, errors.New("tls: ecdhe client key exchange length not enougth")
	}
	if ckx.ciphertext[0] != namedCurveType {
		return nil, errors.New("tls: not SM2 curve")
	}

	ka.curveid = CurveID(ckx.ciphertext[1])<<8 | CurveID(ckx.ciphertext[2])
	//according to GMT0024, we don't care about
	if ka.curveid != 0 && ka.curveid != CurveSM2 {
		return nil, errors.New(fmt.Sprintf("tls: GM ecdhe only unsupported %d curve", CurveSM2))
	}

	ciphertextPubKey := ckx.ciphertext[4:]
	if int(ckx.ciphertext[3]) != len(ciphertextPubKey) {
		return nil, errors.New("tls: ciphertext length of ecdhe client key exchange not match")
	}
	x, y := elliptic.Unmarshal(sm2.P256Sm2(), ciphertextPubKey) // Unmarshal also checks whether the given point is on the curve
	if x == nil {
		return nil, errClientKeyExchange
	}
	ka.peerPublicKey = &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}

	preMasterSecret, err := ka.sm2KapComputeKey()
	if err != nil {
		return nil, err
	}

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreementGM) sm2KapComputeKey() ([]byte, error) {
	userId := []byte{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'}
	var keyExchange func(int, []byte, []byte, *sm2.PrivateKey, *sm2.PublicKey, *sm2.PrivateKey, *sm2.PublicKey) (k []byte, s1 []byte, s2 []byte, err error)
	if ka.isServer {
		keyExchange = sm2.KeyExchangeA
	} else {
		keyExchange = sm2.KeyExchangeB
	}

	var peerPublicKey *sm2.PublicKey
	if ecdsaPublicKey, ok := ka.peerCert.PublicKey.(*ecdsa.PublicKey); ok {
		peerPublicKey = &sm2.PublicKey{
			Curve: sm2.P256Sm2(),
			X:     ecdsaPublicKey.X,
			Y:     ecdsaPublicKey.Y,
		}
	} else {
		peerPublicKey = ka.peerCert.PublicKey.(*sm2.PublicKey)
	}

	secret, _, _, err := keyExchange(48, userId, userId, ka.encCert.PrivateKey.(*sm2.PrivateKey), peerPublicKey, ka.privateKey, ka.peerPublicKey)

	return secret, err
}

func (ka *ecdheKeyAgreementGM) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != namedCurveType { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	ka.curveid = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
	//according to GMT0024, we don't care about
	if ka.curveid != CurveSM2 {
		return errors.New(fmt.Sprintf("tls: GM ecdhe only unsupported %d curve", CurveSM2))
	}

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHParams := skx.key[:4+publicLen]
	publicKey := serverECDHParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	x, y := elliptic.Unmarshal(sm2.P256Sm2(), publicKey) // Unmarshal also checks whether the given point is on the curve
	if x == nil {
		return errServerKeyExchange
	}
	ka.peerPublicKey = &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}

	var signatureAlgorithm SignatureScheme
	_, sigType, hashFunc, err := pickSignatureAlgorithm(cert.PublicKey, []SignatureScheme{signatureAlgorithm}, clientHello.supportedSignatureAlgorithms, ka.version)

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	digest, err := hashForServerKeyExchange(sigType, hashFunc, ka.version, clientHello.random, serverHello.random, serverECDHParams)
	if err != nil {
		return err
	}
	return verifyHandshakeSignature(sigType, cert.PublicKey, hashFunc, digest, sig)
}

func (ka *ecdheKeyAgreementGM) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.curveid == 0 {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	if ka.curveid != CurveSM2 {
		return nil, nil, errors.New("tls: server selected unsupported curve")
	}

	var err error
	ka.privateKey, err = sm2.GenerateKey(config.rand())
	if err != nil {
		return nil, nil, err
	}

	serializedPublicKey := elliptic.Marshal(sm2.P256Sm2(), ka.privateKey.X, ka.privateKey.Y)

	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 4+len(serializedPublicKey))
	ckx.ciphertext[0] = namedCurveType
	ckx.ciphertext[1] = byte(ka.curveid << 8)
	ckx.ciphertext[2] = byte(ka.curveid & 0xff)
	ckx.ciphertext[3] = byte(len(serializedPublicKey))
	copy(ckx.ciphertext[4:], serializedPublicKey)

	preMasterSecret, err := ka.sm2KapComputeKey()
	if err != nil {
		return nil, nil, err
	}

	return preMasterSecret, ckx, nil
}

// eccKeyAgreementGM implements a TLS key agreement where the server
// generates an ephemeral SM2 public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH.
type eccKeyAgreementGM struct {
	version    uint16
	privateKey []byte
	curveid    CurveID

	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int

	//cert for encipher referred to GMT0024
	encipherCert *x509.Certificate
}

func (ka *eccKeyAgreementGM) generateServerKeyExchange(config *Config, signCert, cipherCert *Certificate,
	clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	// mod by syl only one cert
	//digest := ka.hashForServerKeyExchange(clientHello.random, hello.random, cert.Certificate[1])
	digest := ka.hashForServerKeyExchange(clientHello.random, hello.random, cipherCert.Certificate[0])

	priv, ok := signCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}
	sig, err := priv.Sign(config.rand(), digest, nil)
	if err != nil {
		return nil, err
	}

	len := len(sig)

	ske := new(serverKeyExchangeMsg)
	ske.key = make([]byte, len+2)
	ske.key[0] = byte(len >> 8)
	ske.key[1] = byte(len)
	copy(ske.key[2:], sig)

	return ske, nil
}

func (ka *eccKeyAgreementGM) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 {
		return nil, errClientKeyExchange
	}

	if int(ckx.ciphertext[0]<<8|ckx.ciphertext[1]) != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}

	cipher := ckx.ciphertext[2:]

	decrypter, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}

	plain, err := decrypter.Decrypt(config.rand(), cipher, nil)
	if err != nil {
		return nil, err
	}

	if len(plain) != 48 {
		return nil, errClientKeyExchange
	}

	//we do not examine the version here according to openssl practice
	return plain, nil
}

func (ka *eccKeyAgreementGM) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) <= 2 {
		return errServerKeyExchange
	}
	sigLen := int(int(skx.key[0])<<8 | int(skx.key[1]))
	if sigLen+2 != len(skx.key) {
		return errServerKeyExchange
	}
	sig := skx.key[2:]

	digest := ka.hashForServerKeyExchange(clientHello.random, serverHello.random, ka.encipherCert.Raw)

	//verify
	pubKey, _ := cert.PublicKey.(*ecdsa.PublicKey)
	if pubKey.Curve != sm2.P256Sm2() {
		return errors.New("tls: sm2 signing requires a sm2 public key")
	}

	ecdsaSig := new(ecdsaSignature)
	rest, err := asn1.Unmarshal(sig, ecdsaSig)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("tls:processServerKeyExchange: sm2 get signature failed")
	}
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return errors.New("tls: processServerKeyExchange: sm2 signature contained zero or negative values")
	}

	sm2PubKey := sm2.PublicKey{
		Curve: pubKey.Curve,
		X:     pubKey.X,
		Y:     pubKey.Y,
	}

	if !sm2PubKey.Verify(digest, sig) {
		return errors.New("tls: processServerKeyExchange: sm2 verification failure")
	}

	return nil
}

func (ka *eccKeyAgreementGM) hashForServerKeyExchange(slices ...[]byte) []byte {
	buffer := new(bytes.Buffer)
	for i, slice := range slices {
		if i == 2 {
			buffer.Write([]byte{byte(len(slice) >> 16), byte(len(slice) >> 8), byte(len(slice))})
		}
		buffer.Write(slice)
	}
	return buffer.Bytes()
}

func (ka *eccKeyAgreementGM) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, _ *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}
	pubKey := ka.encipherCert.PublicKey.(*ecdsa.PublicKey)
	sm2PubKey := &sm2.PublicKey{Curve: pubKey.Curve, X: pubKey.X, Y: pubKey.Y}
	encrypted, err := sm2.Encrypt(sm2PubKey, preMasterSecret, config.rand())
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}
