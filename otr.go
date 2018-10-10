package gotrax

import (
	"bytes"
	"crypto/dsa"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/otrv4/ed448"
)

type ClientProfile struct {
	InstanceTag           uint32
	PublicKey             *PublicKey
	ForgingKey            *PublicKey
	Versions              []byte
	Expiration            time.Time
	DsaKey                *dsa.PublicKey
	TransitionalSignature []byte
	Sig                   *EddsaSignature
}

type PrekeyProfile struct {
	InstanceTag  uint32
	Expiration   time.Time
	SharedPrekey *PublicKey
	Sig          *EddsaSignature
}

type PrekeyMessage struct {
	Identifier  uint32
	InstanceTag uint32
	Y           ed448.Point
	B           *big.Int
}

func (m *ClientProfile) Validate(tag uint32) error {
	if m.InstanceTag != tag {
		return errors.New("invalid instance tag in client profile")
	}

	if m.PublicKey == nil {
		return errors.New("missing public key in client profile")
	}

	if m.ForgingKey == nil {
		return errors.New("missing forging key in client profile")
	}

	if m.Sig == nil {
		return errors.New("missing signature in client profile")
	}

	if !ed448.DSAVerify(m.Sig.s, m.PublicKey.k, m.SerializeForSignature()) {
		return errors.New("invalid signature in client profile")
	}

	if m.Expiration.Before(time.Now()) {
		return errors.New("client profile has expired")
	}

	if !bytes.Contains(m.Versions, []byte{'4'}) {
		return errors.New("client profile doesn't support version 4")
	}

	// This branch will be untested for now, since I have NO idea how to generate
	// a valid private key AND eddsa signature that matches an invalid point...
	if ValidatePoint(m.PublicKey.k) != nil {
		return errors.New("client profile public key is not a valid point")
	}

	// See comment above about validating the point
	if ValidatePoint(m.ForgingKey.k) != nil {
		return errors.New("client profile forging key is not a valid point")
	}

	// The spec says to verify the DSA transitional signature here
	// For now, I'll avoid doing that, since the purpose of the transitional
	// signature has nothing to do with the prekey server

	return nil
}

func (m *ClientProfile) Equals(other *ClientProfile) bool {
	return bytes.Equal(m.Serialize(), other.Serialize())
}

func (m *ClientProfile) GenerateSignature(kp *Keypair) [114]byte {
	msg := m.SerializeForSignature()
	return ed448.DSASign(kp.Sym, kp.Pub.k, msg)
}

func (m *ClientProfile) HasExpired() bool {
	return m.Expiration.Before(time.Now())
}

func (pp *PrekeyProfile) Equals(other *PrekeyProfile) bool {
	return bytes.Equal(pp.Serialize(), other.Serialize())
}

func (pm *PrekeyMessage) Equals(other *PrekeyMessage) bool {
	return bytes.Equal(pm.Serialize(), other.Serialize())
}

func (pp *PrekeyProfile) GenerateSignature(kp *Keypair) [114]byte {
	msg := pp.SerializeForSignature()
	return ed448.DSASign(kp.Sym, kp.Pub.k, msg)
}

func (pp *PrekeyProfile) Validate(tag uint32, pub *PublicKey) error {
	if pp.InstanceTag != tag {
		return errors.New("invalid instance tag in prekey profile")
	}

	if !ed448.DSAVerify(pp.Sig.s, pub.k, pp.SerializeForSignature()) {
		return errors.New("invalid signature in prekey profile")
	}

	if pp.HasExpired() {
		return errors.New("prekey profile has expired")
	}

	if ValidatePoint(pp.SharedPrekey.k) != nil {
		return errors.New("prekey profile shared prekey is not a valid point")
	}

	return nil
}

func (pm *PrekeyMessage) Validate(tag uint32) error {
	if pm.InstanceTag != tag {
		return errors.New("invalid instance tag in prekey message")
	}

	if ValidatePoint(pm.Y) != nil {
		return errors.New("prekey profile Y point is not a valid point")
	}

	if ValidateDHValue(pm.B) != nil {
		return errors.New("prekey profile B value is not a valid DH group member")
	}

	return nil
}

func (pp *PrekeyProfile) HasExpired() bool {
	return pp.Expiration.Before(time.Now())
}

func generatePrekeyProfile(wr WithRandom, tag uint32, expiration time.Time, longTerm *Keypair) (*PrekeyProfile, *Keypair) {
	sharedKey := GenerateKeypair(wr)
	sharedKey.Pub = CreatePublicKey(sharedKey.Pub.k, SharedPrekeyKey)
	pp := &PrekeyProfile{
		InstanceTag:  tag,
		Expiration:   expiration,
		SharedPrekey: sharedKey.Pub,
	}

	pp.Sig = CreateEddsaSignature(pp.GenerateSignature(longTerm))

	return pp, sharedKey
}

func generatePrekeyMessage(wr WithRandom, tag uint32) (*PrekeyMessage, *Keypair, *big.Int, *big.Int) {
	ident := RandomUint32(wr)
	y := GenerateKeypair(wr)
	privB, _ := rand.Int(wr.RandReader(), DHQ)
	pubB := new(big.Int).Exp(G3, privB, DHP)

	return &PrekeyMessage{
		Identifier:  ident,
		InstanceTag: tag,
		Y:           y.Pub.k,
		B:           pubB,
	}, y, privB, pubB
}
