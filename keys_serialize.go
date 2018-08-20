package gotrax

func (p *PublicKey) Serialize() []byte {
	keyType := []byte{0xBA, 0xD0}
	switch p.keyType {
	case Ed448Key:
		keyType = Ed448KeyType
	case SharedPrekeyKey:
		keyType = SharedPrekeyKeyType
	}
	return append(keyType, p.k.DSAEncode()...)
}

func (s *EddsaSignature) Serialize() []byte {
	return s.s[:]
}
