package oberon

import (
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type Blinding struct {
	Value *curves.PointBls12381G1
}

func NewBlinding(data []byte) (*Blinding, error) {
	b := new(Blinding)
	err := b.Create(data)
	return b, err
}

func (b *Blinding) Create(data []byte) error {
	p, err := hashToCurve(data)
	if err != nil {
		return err
	}
	b.Value = p
	return nil
}

func (b Blinding) MarshalBinary() ([]byte, error) {
	return b.Value.ToAffineCompressed(), nil
}

func (b *Blinding) UnmarshalBinary(data []byte) error {
	pt, err := curves.BLS12381G1().NewIdentityPoint().FromAffineCompressed(data)
	if err != nil {
		return err
	}
	if pt.IsIdentity() {
		return fmt.Errorf("invalid token")
	}
	b.Value, _ = pt.(*curves.PointBls12381G1)
	return nil
}

func (b Blinding) MarshalText() ([]byte, error) {
	return json.Marshal(b.Value.ToAffineCompressed())
}

func (b *Blinding) UnmarshalText(in []byte) error {
	var data [48]byte
	err := json.Unmarshal(in, &data)
	if err != nil {
		return err
	}
	pt, err := curves.BLS12381G1().NewIdentityPoint().FromAffineCompressed(data[:])
	if err != nil {
		return err
	}
	b.Value, _ = pt.(*curves.PointBls12381G1)
	return nil
}
