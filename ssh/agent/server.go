// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package saultSshAgent

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/spikeekips/sault/ssh"
	"golang.org/x/crypto/ed25519"
)

// Server wraps an Agent and uses it to implement the agent side of
// the SSH-agent, wire protocol.
type server struct {
	agent Agent
}

func (s *server) processRequestBytes(reqData []byte) []byte {
	rep, err := s.processRequest(reqData)
	if err != nil {
		if err != errLocked {
			// TODO(hanwen): provide better logging interface?
			log.Printf("agent %d: %v", reqData[0], err)
		}
		return []byte{agentFailure}
	}

	if err == nil && rep == nil {
		return []byte{agentSuccess}
	}

	return saultSsh.Marshal(rep)
}

func marshalKey(k *Key) []byte {
	var record struct {
		Blob    []byte
		Comment string
	}
	record.Blob = k.Marshal()
	record.Comment = k.Comment

	return saultSsh.Marshal(&record)
}

// See [PROTOCOL.agent], section 2.5.1.
const agentV1IdentitiesAnswer = 2

type agentV1IdentityMsg struct {
	Numkeys uint32 `sshtype:"2"`
}

type agentRemoveIdentityMsg struct {
	KeyBlob []byte `sshtype:"18"`
}

type agentLockMsg struct {
	Passphrase []byte `sshtype:"22"`
}

type agentUnlockMsg struct {
	Passphrase []byte `sshtype:"23"`
}

func (s *server) processRequest(data []byte) (interface{}, error) {
	switch data[0] {
	case agentRequestV1Identities:
		return &agentV1IdentityMsg{0}, nil

	case agentRemoveAllV1Identities:
		return nil, nil

	case agentRemoveIdentity:
		var req agentRemoveIdentityMsg
		if err := saultSsh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := saultSsh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		return nil, s.agent.Remove(&Key{Format: wk.Format, Blob: req.KeyBlob})

	case agentRemoveAllIdentities:
		return nil, s.agent.RemoveAll()

	case agentLock:
		var req agentLockMsg
		if err := saultSsh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		return nil, s.agent.Lock(req.Passphrase)

	case agentUnlock:
		var req agentLockMsg
		if err := saultSsh.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, s.agent.Unlock(req.Passphrase)

	case agentSignRequest:
		var req signRequestAgentMsg
		if err := saultSsh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := saultSsh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		k := &Key{
			Format: wk.Format,
			Blob:   req.KeyBlob,
		}

		sig, err := s.agent.Sign(k, req.Data) //  TODO(hanwen): flags.
		if err != nil {
			return nil, err
		}
		return &signResponseAgentMsg{SigBlob: saultSsh.Marshal(sig)}, nil

	case agentRequestIdentities:
		keys, err := s.agent.List()
		if err != nil {
			return nil, err
		}

		rep := identitiesAnswerAgentMsg{
			NumKeys: uint32(len(keys)),
		}
		for _, k := range keys {
			rep.Keys = append(rep.Keys, marshalKey(k)...)
		}
		return rep, nil

	case agentAddIdConstrained, agentAddIdentity:
		return nil, s.insertIdentity(data)
	}

	return nil, fmt.Errorf("unknown opcode %d", data[0])
}

func parseRSAKey(req []byte) (*AddedKey, error) {
	var k rsaKeyMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	if k.E.BitLen() > 30 {
		return nil, errors.New("agent: RSA public exponent too large")
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(k.E.Int64()),
			N: k.N,
		},
		D:      k.D,
		Primes: []*big.Int{k.P, k.Q},
	}
	priv.Precompute()

	return &AddedKey{PrivateKey: priv, Comment: k.Comments}, nil
}

func parseEd25519Key(req []byte) (*AddedKey, error) {
	var k ed25519KeyMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(k.Priv)
	return &AddedKey{PrivateKey: &priv, Comment: k.Comments}, nil
}

func parseDSAKey(req []byte) (*AddedKey, error) {
	var k dsaKeyMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Y,
		},
		X: k.X,
	}

	return &AddedKey{PrivateKey: priv, Comment: k.Comments}, nil
}

func unmarshalECDSA(curveName string, keyBytes []byte, privScalar *big.Int) (priv *ecdsa.PrivateKey, err error) {
	priv = &ecdsa.PrivateKey{
		D: privScalar,
	}

	switch curveName {
	case "nistp256":
		priv.Curve = elliptic.P256()
	case "nistp384":
		priv.Curve = elliptic.P384()
	case "nistp521":
		priv.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("agent: unknown curve %q", curveName)
	}

	priv.X, priv.Y = elliptic.Unmarshal(priv.Curve, keyBytes)
	if priv.X == nil || priv.Y == nil {
		return nil, errors.New("agent: point not on curve")
	}

	return priv, nil
}

func parseEd25519Cert(req []byte) (*AddedKey, error) {
	var k ed25519CertMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	pubKey, err := saultSsh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(k.Priv)
	cert, ok := pubKey.(*saultSsh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad ED25519 certificate")
	}
	return &AddedKey{PrivateKey: &priv, Certificate: cert, Comment: k.Comments}, nil
}

func parseECDSAKey(req []byte) (*AddedKey, error) {
	var k ecdsaKeyMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	priv, err := unmarshalECDSA(k.Curve, k.KeyBytes, k.D)
	if err != nil {
		return nil, err
	}

	return &AddedKey{PrivateKey: priv, Comment: k.Comments}, nil
}

func parseRSACert(req []byte) (*AddedKey, error) {
	var k rsaCertMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := saultSsh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}

	cert, ok := pubKey.(*saultSsh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad RSA certificate")
	}

	// An RSA publickey as marshaled by rsaPublicKey.Marshal() in keys.go
	var rsaPub struct {
		Name string
		E    *big.Int
		N    *big.Int
	}
	if err := saultSsh.Unmarshal(cert.Key.Marshal(), &rsaPub); err != nil {
		return nil, fmt.Errorf("agent: Unmarshal failed to parse public key: %v", err)
	}

	if rsaPub.E.BitLen() > 30 {
		return nil, errors.New("agent: RSA public exponent too large")
	}

	priv := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(rsaPub.E.Int64()),
			N: rsaPub.N,
		},
		D:      k.D,
		Primes: []*big.Int{k.Q, k.P},
	}
	priv.Precompute()

	return &AddedKey{PrivateKey: &priv, Certificate: cert, Comment: k.Comments}, nil
}

func parseDSACert(req []byte) (*AddedKey, error) {
	var k dsaCertMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	pubKey, err := saultSsh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*saultSsh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad DSA certificate")
	}

	// A DSA publickey as marshaled by dsaPublicKey.Marshal() in keys.go
	var w struct {
		Name       string
		P, Q, G, Y *big.Int
	}
	if err := saultSsh.Unmarshal(cert.Key.Marshal(), &w); err != nil {
		return nil, fmt.Errorf("agent: Unmarshal failed to parse public key: %v", err)
	}

	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: w.P,
				Q: w.Q,
				G: w.G,
			},
			Y: w.Y,
		},
		X: k.X,
	}

	return &AddedKey{PrivateKey: priv, Certificate: cert, Comment: k.Comments}, nil
}

func parseECDSACert(req []byte) (*AddedKey, error) {
	var k ecdsaCertMsg
	if err := saultSsh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := saultSsh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*saultSsh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad ECDSA certificate")
	}

	// An ECDSA publickey as marshaled by ecdsaPublicKey.Marshal() in keys.go
	var ecdsaPub struct {
		Name string
		ID   string
		Key  []byte
	}
	if err := saultSsh.Unmarshal(cert.Key.Marshal(), &ecdsaPub); err != nil {
		return nil, err
	}

	priv, err := unmarshalECDSA(ecdsaPub.ID, ecdsaPub.Key, k.D)
	if err != nil {
		return nil, err
	}

	return &AddedKey{PrivateKey: priv, Certificate: cert, Comment: k.Comments}, nil
}

func (s *server) insertIdentity(req []byte) error {
	var record struct {
		Type string `sshtype:"17|25"`
		Rest []byte `ssh:"rest"`
	}

	if err := saultSsh.Unmarshal(req, &record); err != nil {
		return err
	}

	var addedKey *AddedKey
	var err error

	switch record.Type {
	case saultSsh.KeyAlgoRSA:
		addedKey, err = parseRSAKey(req)
	case saultSsh.KeyAlgoDSA:
		addedKey, err = parseDSAKey(req)
	case saultSsh.KeyAlgoECDSA256, saultSsh.KeyAlgoECDSA384, saultSsh.KeyAlgoECDSA521:
		addedKey, err = parseECDSAKey(req)
	case saultSsh.KeyAlgoED25519:
		addedKey, err = parseEd25519Key(req)
	case saultSsh.CertAlgoRSAv01:
		addedKey, err = parseRSACert(req)
	case saultSsh.CertAlgoDSAv01:
		addedKey, err = parseDSACert(req)
	case saultSsh.CertAlgoECDSA256v01, saultSsh.CertAlgoECDSA384v01, saultSsh.CertAlgoECDSA521v01:
		addedKey, err = parseECDSACert(req)
	case saultSsh.CertAlgoED25519v01:
		addedKey, err = parseEd25519Cert(req)
	default:
		return fmt.Errorf("agent: not implemented: %q", record.Type)
	}

	if err != nil {
		return err
	}
	return s.agent.Add(*addedKey)
}

// ServeAgent serves the agent protocol on the given connection. It
// returns when an I/O error occurs.
func ServeAgent(agent Agent, c io.ReadWriter) error {
	s := &server{agent}

	var length [4]byte
	for {
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return err
		}
		l := binary.BigEndian.Uint32(length[:])
		if l > maxAgentResponseBytes {
			// We also cap requests.
			return fmt.Errorf("agent: request too large: %d", l)
		}

		req := make([]byte, l)
		if _, err := io.ReadFull(c, req); err != nil {
			return err
		}

		repData := s.processRequestBytes(req)
		if len(repData) > maxAgentResponseBytes {
			return fmt.Errorf("agent: reply too large: %d bytes", len(repData))
		}

		binary.BigEndian.PutUint32(length[:], uint32(len(repData)))
		if _, err := c.Write(length[:]); err != nil {
			return err
		}
		if _, err := c.Write(repData); err != nil {
			return err
		}
	}
}