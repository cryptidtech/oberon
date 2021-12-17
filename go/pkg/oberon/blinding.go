package oberon

import (
	"encoding/json"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
)

type Blinding struct {
	Value *bls12381.PointG1
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
	return g1.ToCompressed(b.Value), nil
}

func (b *Blinding) UnmarshalBinary(data []byte) error {
	p, err := g1.FromCompressed(data)
	if err != nil {
		return err
	}
	if !isValidPointG1(p) {
		return fmt.Errorf("invalid token")
	}
	b.Value = p
	return nil
}

func (b Blinding) MarshalText() ([]byte, error) {
	return json.Marshal(g1.ToCompressed(b.Value))
}

func (b *Blinding) UnmarshalText(in []byte) error {
	var data [48]byte
	err := json.Unmarshal(in, &data)
	if err != nil {
		return err
	}
	return b.UnmarshalBinary(data[:])
}