package oberon

import (
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"golang.org/x/crypto/sha3"
	"io"
)

type SecretKey struct {
	W *curves.ScalarBls12381
	X *curves.ScalarBls12381
	Y *curves.ScalarBls12381
}

func NewSecretKey(reader io.Reader) (*SecretKey, error) {
	curve := curves.BLS12381G2()
	w := curve.NewScalar().Random(reader)
	if w == nil {
		return nil, fmt.Errorf("unable to create secret key")
	}
	x := curve.NewScalar().Random(reader)
	if x == nil {
		return nil, fmt.Errorf("unable to create secret key")
	}
	y := curve.NewScalar().Random(reader)
	if y == nil {
		return nil, fmt.Errorf("unable to create secret key")
	}
	W, _ := w.(*curves.ScalarBls12381)
	X, _ := x.(*curves.ScalarBls12381)
	Y, _ := y.(*curves.ScalarBls12381)
	return &SecretKey{W, X, Y}, nil
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

	var tmp [3]*curves.ScalarBls12381
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
	pk := new(PublicKey)
	pk.FromSecretKey(&s)
	return pk
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
	copy(tmp[:32], s.W.Bytes())
	copy(tmp[32:64], s.X.Bytes())
	copy(tmp[64:96], s.Y.Bytes())
	return tmp[:], nil
}

func (s *SecretKey) UnmarshalBinary(in []byte) error {
	if len(in) != 96 {
		return fmt.Errorf("invalid length")
	}
	var t [native.FieldBytes]byte
	copy(t[:], in[:32])
	curve := curves.BLS12381G2()
	w, err := bls12381.Bls12381FqNew().SetBytes(&t)
	if err != nil {
		return err
	}
	copy(t[:], in[32:64])
	x, err := bls12381.Bls12381FqNew().SetBytes(&t)
	if err != nil {
		return err
	}
	copy(t[:], in[64:96])
	y, err := bls12381.Bls12381FqNew().SetBytes(&t)
	if err != nil {
		return err
	}
	if w.IsZero()|x.IsZero()|y.IsZero() == 1 {
		return fmt.Errorf("invalid secret key")
	}
	s.W, _ = curve.NewScalar().(*curves.ScalarBls12381)
	s.X, _ = curve.NewScalar().(*curves.ScalarBls12381)
	s.Y, _ = curve.NewScalar().(*curves.ScalarBls12381)
	s.W.Value = w
	s.X.Value = x
	s.Y.Value = y
	return nil
}

func (s SecretKey) MarshalText() ([]byte, error) {
	tmp := map[string][]byte{
		"w": s.W.Bytes(),
		"x": s.X.Bytes(),
		"y": s.Y.Bytes(),
	}
	return json.Marshal(&tmp)
}

func (s *SecretKey) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var w, x, y *native.Field
	var t [native.FieldBytes]byte

	curve := curves.BLS12381G2()
	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if wBytes, ok := tmp["w"]; ok {
		if len(wBytes) != native.FieldBytes {
			return fmt.Errorf("invalid byte sequence")
		}
		copy(t[:], wBytes)
		w, err = bls12381.Bls12381FqNew().SetBytes(&t)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'w'")
	}

	if xBytes, ok := tmp["x"]; ok {
		if len(xBytes) != native.FieldBytes {
			return fmt.Errorf("invalid byte sequence")
		}
		copy(t[:], xBytes)
		x, err = bls12381.Bls12381FqNew().SetBytes(&t)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'x'")
	}

	if yBytes, ok := tmp["y"]; ok {
		if len(yBytes) != native.FieldBytes {
			return fmt.Errorf("invalid byte sequence")
		}
		copy(t[:], yBytes)
		y, err = bls12381.Bls12381FqNew().SetBytes(&t)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'y'")
	}

	if w.IsZero()|x.IsZero()|y.IsZero() == 1 {
		return fmt.Errorf("invalid secret key")
	}

	s.W, _ = curve.NewScalar().(*curves.ScalarBls12381)
	s.X, _ = curve.NewScalar().(*curves.ScalarBls12381)
	s.Y, _ = curve.NewScalar().(*curves.ScalarBls12381)

	s.W.Value = w
	s.X.Value = x
	s.Y.Value = y

	return nil
}
