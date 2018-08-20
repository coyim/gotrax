package gotrax

import (
	"crypto/dsa"
	"time"
)

func (cp *ClientProfile) SerializeForSignature() []byte {
	out := []byte{}
	fields := uint32(4)

	if cp.DsaKey != nil {
		fields++
	}

	if cp.TransitionalSignature != nil {
		fields++
	}

	out = AppendWord(out, fields)

	out = AppendShort(out, ClientProfileTagInstanceTag)
	out = AppendWord(out, cp.InstanceTag)

	out = AppendShort(out, ClientProfileTagPublicKey)
	out = append(out, cp.PublicKey.Serialize()...)

	out = AppendShort(out, ClientProfileTagVersions)
	out = append(out, SerializeVersions(cp.Versions)...)

	out = AppendShort(out, ClientProfileTagExpiry)
	out = append(out, SerializeExpiry(cp.Expiration)...)

	if cp.DsaKey != nil {
		out = AppendShort(out, ClientProfileTagDSAKey)
		out = append(out, SerializeDSAKey(cp.DsaKey)...)
	}

	if cp.TransitionalSignature != nil {
		out = AppendShort(out, ClientProfileTagTransitionalSignature)
		out = append(out, cp.TransitionalSignature...)
	}

	return out
}

func (cp *ClientProfile) Serialize() []byte {
	return append(cp.SerializeForSignature(), cp.Sig.Serialize()...)
}

func SerializeVersions(v []byte) []byte {
	return AppendData(nil, v)
}

func SerializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return AppendLong(nil, uint64(val))
}

func SerializeDSAKey(k *dsa.PublicKey) []byte {
	result := DsaKeyType
	result = AppendMPI(result, k.P)
	result = AppendMPI(result, k.Q)
	result = AppendMPI(result, k.G)
	result = AppendMPI(result, k.Y)
	return result
}
