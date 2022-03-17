package oberon

import (
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
)

type Token struct {
	Value *curves.PointBls12381G1
}

func NewToken(sk *SecretKey, id []byte) (*Token, error) {
	t := new(Token)
	err := t.Create(sk, id)
	return t, err
}

// Create a new token
func (t *Token) Create(sk *SecretKey, id []byte) error {
	m, err := computeM(id)
	if err != nil {
		return err
	}
	mTick, err := computeMTick(m)
	if err != nil {
		return err
	}
	u, err := computeU(mTick)
	if err != nil {
		return err
	}

	tv1 := sk.W.Mul(mTick)
	tv2 := sk.Y.Mul(m)
	e := sk.X.Add(tv1).Add(tv2)

	// u * (x + w * m' + y * m)
	sigma := u.Mul(e).(*curves.PointBls12381G1)

	if !isValidPointG1(sigma) {
		return fmt.Errorf("invalid token")
	}
	t.Value = sigma
	return nil
}

// Verify whether the token is valid to the public key
func (t *Token) Verify(pk *PublicKey, id []byte) error {
	m, err := computeM(id)
	if err != nil {
		return err
	}
	mTick, err := computeMTick(m)
	if err != nil {
		return err
	}

	u, err := computeU(mTick)
	if err != nil {
		return err
	}
	curve := curves.BLS12381G2()
	rhs := curve.NewIdentityPoint().SumOfProducts([]curves.Point{pk.W, pk.X, pk.Y}, []curves.Scalar{mTick, curve.NewScalar().One(), m}).(*curves.PointBls12381G2)
	g := curve.NewGeneratorPoint().(*curves.PointBls12381G2)

	engine := new(bls12381.Engine)
	engine.AddPairInvG1(u.Value, rhs.Value)
	engine.AddPair(t.Value.Value, g.Value)
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("check failed")
	}
}

func (t *Token) ApplyBlinding(token *Token, b *Blinding) *Token {
	t.Value, _ = token.Value.Sub(b.Value).(*curves.PointBls12381G1)
	return t
}

func (t *Token) RemoveBlinding(token *Token, b *Blinding) *Token {
	t.Value, _ = token.Value.Add(b.Value).(*curves.PointBls12381G1)
	return t
}

func (t Token) MarshalBinary() ([]byte, error) {
	return t.Value.ToAffineCompressed(), nil
}

func (t *Token) UnmarshalBinary(data []byte) error {
	tt, err := t.Value.FromAffineCompressed(data)
	if err != nil {
		return err
	}
	t.Value = tt.(*curves.PointBls12381G1)
	return nil
}

func (t Token) MarshalText() ([]byte, error) {
	return json.Marshal(t.Value.ToAffineCompressed())
}

func (t *Token) UnmarshalText(in []byte) error {
	var data [48]byte
	err := json.Unmarshal(in, &data)
	if err != nil {
		return err
	}
	return t.UnmarshalBinary(data[:])
}
