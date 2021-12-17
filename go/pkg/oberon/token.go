package oberon

import (
	"encoding/json"
	"fmt"
	bls12381 "github.com/mikelodder7/bls12-381"
)


type Token struct {
	Value *bls12381.PointG1
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

	e := bls12381.NewFr()
	tv1 := bls12381.NewFr()
	tv2 := bls12381.NewFr()

	tv2.Mul(sk.Y, m)
	tv1.Mul(sk.W, mTick)
	e.Add(sk.X, tv1)
	e.Add(e, tv2)
	// u * (x + w * m' + y * m)
	sigma := g1.MulScalar(g1.New(), u, e)

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
	rhs, err := g2.MultiExp(g2.New(), []*bls12381.PointG2{pk.W, pk.X, pk.Y}, []*bls12381.Fr{mTick, bls12381.NewFr().One(), m})
	if err != nil {
		return err
	}

	engine := bls12381.NewEngine()
	engine.AddPairInv(u, rhs)
	engine.AddPair(t.Value, genG2)
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("check failed")
	}
}

func (t *Token) ApplyBlinding(token *Token, b *Blinding) *Token {
	t.Value = g1.New()
	g1.Sub(t.Value, token.Value, b.Value)
	return t
}

func (t *Token) RemoveBlinding(token *Token, b *Blinding) *Token {
	t.Value = g1.New()
	g1.Add(t.Value, token.Value, b.Value)
	return t
}

func (t Token) MarshalBinary() ([]byte, error) {
	return g1.ToCompressed(t.Value), nil
}

func (t *Token) UnmarshalBinary(data []byte) error {
	p, err := g1.FromCompressed(data)
	if err != nil {
		return err
	}
	if !isValidPointG1(p) {
		return fmt.Errorf("invalid token")
	}
	t.Value = p
	return nil
}

func (t Token) MarshalText() ([]byte, error) {
	return json.Marshal(g1.ToCompressed(t.Value))
}

func (t *Token) UnmarshalText(in []byte) error {
	var data [48]byte
	err := json.Unmarshal(in, &data)
	if err != nil {
		return err
	}
	return t.UnmarshalBinary(data[:])
}
