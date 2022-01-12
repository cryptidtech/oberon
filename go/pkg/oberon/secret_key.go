package oberon

import (
	"encoding/json"
	"fmt"
	bls12381 "github.com/mikelodder7/bls12-381"
	"golang.org/x/crypto/sha3"
	"io"
)

type SecretKey struct {
	W *bls12381.Fr
	X *bls12381.Fr
	Y *bls12381.Fr
}

func NewSecretKey(reader io.Reader) (*SecretKey, error) {
	w, err := bls12381.NewFr().Rand(reader)
	if err != nil {
		return nil, err
	}
	x, err := bls12381.NewFr().Rand(reader)
	if err != nil {
		return nil, err
	}
	y, err := bls12381.NewFr().Rand(reader)
	if err != nil {
		return nil, err
	}
	return &SecretKey{w, x, y}, nil
}

func HashSecretKey(data []byte) (*SecretKey, error) {
	hasher := sha3.NewShake256()
	n, err := hasher.Write(toScalarDst)
	if err != nil {
		return nil, err
	}
	if n != len(toScalarDst) {
		return nil, fmt.Errorf("unable to write %d bytes", len(toScalarDst))
	}
	n, err = hasher.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, fmt.Errorf("unable to write %d bytes", len(data))
	}

	var tmp [3]*bls12381.Fr
	var scalar [48]byte
	for i := 0; i < 3; i++ {
		n, err = hasher.Read(scalar[:])
		if err != nil {
			return nil, err
		}
		if n != len(scalar) {
			return nil, fmt.Errorf("unable to write %d bytes", len(scalar))
		}

		tmp[i] = fromOkm(scalar[:])
	}
	return &SecretKey{
		W: tmp[0], X: tmp[1], Y: tmp[2],
	}, nil
}

func (s SecretKey) PublicKey() *PublicKey {
	w := g2.One()
	x := g2.One()
	y := g2.One()

	g2.MulScalar(w, w, s.W)
	g2.MulScalar(x, x, s.X)
	g2.MulScalar(y, y, s.Y)
	return &PublicKey{
		W: w,
		X: x,
		Y: y,
	}
}

func (s *SecretKey) Sign(id []byte) (*Token, error) {
	t := new(Token)
	err := t.Create(s, id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s SecretKey) MarshalBinary() ([]byte, error) {
	var tmp [96]byte
	copy(tmp[:32], reverseBytes(s.W.ToBytes()))
	copy(tmp[32:64], reverseBytes(s.X.ToBytes()))
	copy(tmp[64:96], reverseBytes(s.Y.ToBytes()))
	return tmp[:], nil
}

func (s *SecretKey) UnmarshalBinary(in []byte) error {
	if len(in) != 96 {
		return fmt.Errorf("invalid length")
	}
	s.W = bls12381.NewFr().FromBytes(reverseBytes(in[:32]))
	s.X = bls12381.NewFr().FromBytes(reverseBytes(in[32:64]))
	s.Y = bls12381.NewFr().FromBytes(reverseBytes(in[64:96]))
	if s.W.IsZero() || s.X.IsZero() || s.Y.IsZero() {
		return fmt.Errorf("invalid secret key")
	}
	return nil
}

func (s SecretKey) MarshalText() ([]byte, error) {
	tmp := map[string][]byte{
		"w": reverseBytes(s.W.ToBytes()),
		"x": reverseBytes(s.X.ToBytes()),
		"y": reverseBytes(s.Y.ToBytes()),
	}
	return json.Marshal(&tmp)
}

func (s *SecretKey) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var w, x, y *bls12381.Fr

	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if wBytes, ok := tmp["w"]; ok {
		w = bls12381.NewFr().FromBytes(reverseBytes(wBytes))
	} else {
		return fmt.Errorf("missing expected map key 'w'")
	}

	if xBytes, ok := tmp["x"]; ok {
		x = bls12381.NewFr().FromBytes(reverseBytes(xBytes))
	} else {
		return fmt.Errorf("missing expected map key 'x'")
	}

	if yBytes, ok := tmp["y"]; ok {
		y = bls12381.NewFr().FromBytes(reverseBytes(yBytes))
	} else {
		return fmt.Errorf("missing expected map key 'y'")
	}

	s.W = w
	s.X = x
	s.Y = y

	if s.W.IsZero() || s.X.IsZero() || s.Y.IsZero() {
		return fmt.Errorf("invalid secret key")
	}
	return nil
}
