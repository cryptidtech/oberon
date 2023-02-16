package oberon

import (
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"io"
)

const proofBytes = 96

type Proof struct {
	UTick, Z *curves.PointBls12381G1
}

func NewProof(token *Token, blindings []*Blinding, id, nonce []byte, rng io.Reader) (*Proof, error) {
	p := new(Proof)
	err := p.Create(token, blindings, id, nonce, rng)
	return p, err
}

func (p *Proof) Create(
	token *Token,
	blindings []*Blinding,
	id, nonce []byte,
	rng io.Reader,
) error {
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

	r := genRndScalar(rng)
	uTick := u.Mul(r)

	t, err := hashToScalar([][]byte{
		uTick.ToAffineCompressed(),
		nonce,
	})
	if err != nil {
		return err
	}

	rat := r.Add(t)
	z := curves.BLS12381G1().NewIdentityPoint()
	z = z.Add(token.Value)
	for _, b := range blindings {
		z = z.Add(b.Value)
	}
	z = z.Mul(rat)

	p.UTick = uTick.(*curves.PointBls12381G1)
	p.Z = z.Neg().(*curves.PointBls12381G1)
	return nil
}

func (p Proof) Open(
	pk *PublicKey,
	id, nonce []byte,
) error {
	goodProof := isValidPointG1(p.Z)
	goodUTick := isValidPointG1(p.UTick)

	if !goodProof || !goodUTick {
		return fmt.Errorf("invalid proof")
	}

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
	t, err := hashToScalar([][]byte{
		p.UTick.ToAffineCompressed(),
		nonce,
	})
	if err != nil {
		return err
	}
	lhs := p.UTick.Add(u.Mul(t)).(*curves.PointBls12381G1)
	rhs := pk.X.Add(pk.Y.Mul(m)).Add(pk.W.Mul(mTick)).(*curves.PointBls12381G2)
	g2 := curves.BLS12381G2().NewGeneratorPoint().(*curves.PointBls12381G2)

	engine := new(bls12381.Engine)
	engine.AddPair(lhs.Value, rhs.Value)
	engine.AddPair(p.Z.Value, g2.Value)
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("check failed")
	}
}

func (p Proof) MarshalBinary() ([]byte, error) {
	var tmp [proofBytes]byte
	copy(tmp[:48], p.UTick.ToAffineCompressed())
	copy(tmp[48:], p.Z.ToAffineCompressed())
	return tmp[:], nil
}

func (p *Proof) UnmarshalBinary(in []byte) error {
	curve := curves.BLS12381(new(curves.PointBls12381G1))
	if len(in) != proofBytes {
		return fmt.Errorf("invalid length")
	}
	utick, err := curve.NewG1IdentityPoint().FromAffineCompressed(in[:48])
	if err != nil {
		return err
	}
	z, err := curve.NewG1IdentityPoint().FromAffineCompressed(in[48:])
	if err != nil {
		return err
	}

	Z, _ := z.(*curves.PointBls12381G1)
	UTick, _ := utick.(*curves.PointBls12381G1)

	goodProof := isValidPointG1(Z)
	goodUTick := isValidPointG1(UTick)

	if goodProof && goodUTick {
		p.Z = Z
		p.UTick = UTick
		return nil
	}
	return fmt.Errorf("invalid proof")
}

func (p Proof) MarshalText() ([]byte, error) {
	tmp := map[string][]byte{
		"z":      p.Z.ToAffineCompressed(),
		"u_tick": p.UTick.ToAffineCompressed(),
	}
	return json.Marshal(&tmp)
}

func (p *Proof) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var z, uTick *curves.PointBls12381G1

	curve := curves.BLS12381(new(curves.PointBls12381G1))
	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if proofBytes, ok := tmp["z"]; ok {
		pf, err := curve.NewG1IdentityPoint().FromAffineCompressed(proofBytes)
		if err != nil {
			return err
		}
		z, _ = pf.(*curves.PointBls12381G1)
	} else {
		return fmt.Errorf("missing expected map key 'proof'")
	}

	if uTickBytes, ok := tmp["u_tick"]; ok {
		ut, err := curve.NewG1IdentityPoint().FromAffineCompressed(uTickBytes)
		if err != nil {
			return err
		}
		uTick, _ = ut.(*curves.PointBls12381G1)
	} else {
		return fmt.Errorf("missing expected map key 'u_tick'")
	}

	goodProof := isValidPointG1(z)
	goodUTick := isValidPointG1(uTick)
	if goodProof && goodUTick {
		p.Z = z
		p.UTick = uTick
		return nil
	}
	return fmt.Errorf("invalid proof")
}

func genRndScalar(rng io.Reader) *curves.ScalarBls12381 {
	curve := curves.BLS12381G1()
	s := curve.NewScalar().Random(rng)
	for s.IsZero() || s.IsOne() {
		s = s.Random(rng)
	}
	r, _ := s.(*curves.ScalarBls12381)
	return r
}
