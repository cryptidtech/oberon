package oberon

import (
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"io"
)

const proofBytes = 256

type Proof struct {
	Proof, UTick       *curves.PointBls12381G1
	Commitment         *curves.PointBls12381G2
	Challenge, Schnorr *curves.ScalarBls12381
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

	t := genRndScalar(rng)
	tt := genRndScalar(rng)
	r := genRndScalar(rng)
	uTick := u.Mul(r)
	points := make([]curves.Point, 0, 2+len(blindings))
	scalars := make([]curves.Scalar, 0, 2+len(blindings))

	points = append(points, uTick)
	scalars = append(scalars, t)

	points = append(points, token.Value)
	scalars = append(scalars, r)

	for _, b := range blindings {
		points = append(points, b.Value)
		scalars = append(scalars, r)
	}

	proof := u.SumOfProducts(points, scalars)
	if proof == nil {
		return nil
	}
	curve := curves.BLS12381G2()

	commitment := curve.ScalarBaseMult(t)
	proving := curve.ScalarBaseMult(tt)

	challenge, err := hashToScalar([][]byte{
		id,
		uTick.ToAffineCompressed(),
		proof.ToAffineCompressed(),
		commitment.ToAffineCompressed(),
		proving.ToAffineCompressed(),
		nonce,
	})
	if err != nil {
		return err
	}
	tv := challenge.Mul(t)
	schnorr := tt.Sub(tv)

	p.Proof = proof.(*curves.PointBls12381G1)
	p.UTick = uTick.(*curves.PointBls12381G1)
	p.Commitment = commitment.(*curves.PointBls12381G2)
	p.Challenge = challenge
	p.Schnorr = schnorr.(*curves.ScalarBls12381)
	return nil
}

func (p Proof) Open(
	pk *PublicKey,
	id, nonce []byte,
) error {
	goodProof := isValidPointG1(p.Proof)
	goodUTick := isValidPointG1(p.UTick)
	goodComm := isValidPointG2(p.Commitment)

	if !goodProof || !goodUTick || !goodComm ||
		p.Challenge.IsZero() || p.Schnorr.IsZero() {
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

	curve := curves.BLS12381G2()
	g2 := curve.NewGeneratorPoint().(*curves.PointBls12381G2)
	proving := g2.SumOfProducts(
		[]curves.Point{g2, p.Commitment},
		[]curves.Scalar{p.Schnorr, p.Challenge},
	)
	if proving == nil {
		return fmt.Errorf("invalid proof")
	}

	challenge, err := hashToScalar([][]byte{
		id,
		p.UTick.ToAffineCompressed(),
		p.Proof.ToAffineCompressed(),
		p.Commitment.ToAffineCompressed(),
		proving.ToAffineCompressed(),
		nonce,
	})
	if err != nil {
		return err
	}
	if challenge == nil || challenge.Value.Equal(p.Challenge.Value) == 0 {
		return fmt.Errorf("invalid challenge")
	}

	rhs := g2.SumOfProducts(
		[]curves.Point{pk.W, pk.X, pk.Y, p.Commitment},
		[]curves.Scalar{mTick, curve.NewScalar().One(), m, curve.NewScalar().One()})
	if rhs == nil {
		return fmt.Errorf("invalid proof")
	}
	r := rhs.(*curves.PointBls12381G2)
	engine := new(bls12381.Engine)
	engine.AddPairInvG1(p.UTick.Value, r.Value)
	engine.AddPair(p.Proof.Value, g2.Value)
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("check failed")
	}
}

func (p Proof) MarshalBinary() ([]byte, error) {
	var tmp [proofBytes]byte
	copy(tmp[:48], p.Proof.ToAffineCompressed())
	copy(tmp[48:96], p.UTick.ToAffineCompressed())
	copy(tmp[96:192], p.Commitment.ToAffineCompressed())
	copy(tmp[192:224], p.Challenge.Bytes())
	copy(tmp[224:], p.Schnorr.Bytes())
	return tmp[:], nil
}

func (p *Proof) UnmarshalBinary(in []byte) error {
	curve := curves.BLS12381(new(curves.PointBls12381G1))
	if len(in) != proofBytes {
		return fmt.Errorf("invalid length")
	}
	proof, err := curve.NewG1IdentityPoint().FromAffineCompressed(in[:48])
	if err != nil {
		return err
	}
	uTick, err := curve.NewG1IdentityPoint().FromAffineCompressed(in[48:96])
	if err != nil {
		return err
	}
	commitment, err := curve.NewG2IdentityPoint().FromAffineCompressed(in[96:192])
	if err != nil {
		return err
	}
	challenge, err := curve.NewScalar().SetBytes(in[192:224])
	if err != nil {
		return err
	}
	schnorr, err := curve.NewScalar().SetBytes(in[224:])
	if err != nil {
		return err
	}

	Proof, _ := proof.(*curves.PointBls12381G1)
	UTick, _ := uTick.(*curves.PointBls12381G1)
	Commitment, _ := commitment.(*curves.PointBls12381G2)

	goodProof := isValidPointG1(Proof)
	goodUTick := isValidPointG1(UTick)
	goodComm := isValidPointG2(Commitment)

	if goodProof && goodUTick && goodComm && !challenge.IsZero() && !schnorr.IsZero() {
		p.Proof = Proof
		p.UTick = UTick
		p.Commitment = Commitment
		p.Challenge, _ = challenge.(*curves.ScalarBls12381)
		p.Schnorr, _ = schnorr.(*curves.ScalarBls12381)
		return nil
	}
	return fmt.Errorf("invalid proof")
}

func (p Proof) MarshalText() ([]byte, error) {
	tmp := map[string][]byte{
		"proof":      p.Proof.ToAffineCompressed(),
		"u_tick":     p.UTick.ToAffineCompressed(),
		"commitment": p.Commitment.ToAffineCompressed(),
		"challenge":  p.Challenge.Bytes(),
		"schnorr":    p.Schnorr.Bytes(),
	}
	return json.Marshal(&tmp)
}

func (p *Proof) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var proof, uTick *curves.PointBls12381G1
	var commitment *curves.PointBls12381G2
	var challenge, schnorr *curves.ScalarBls12381

	curve := curves.BLS12381(new(curves.PointBls12381G1))
	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if proofBytes, ok := tmp["proof"]; ok {
		pf, err := curve.NewG1IdentityPoint().FromAffineCompressed(proofBytes)
		if err != nil {
			return err
		}
		proof, _ = pf.(*curves.PointBls12381G1)
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
	if commitmentBytes, ok := tmp["commitment"]; ok {
		com, err := curve.NewG2IdentityPoint().FromAffineCompressed(commitmentBytes)
		if err != nil {
			return err
		}
		commitment, _ = com.(*curves.PointBls12381G2)
	} else {
		return fmt.Errorf("missing expected mak key 'commitment'")
	}
	if challengeBytes, ok := tmp["challenge"]; ok {
		chal, err := curve.NewScalar().SetBytes(challengeBytes)
		if err != nil {
			return err
		}
		challenge, _ = chal.(*curves.ScalarBls12381)
	}
	if schnorrBytes, ok := tmp["schnorr"]; ok {
		sch, err := curve.NewScalar().SetBytes(schnorrBytes)
		if err != nil {
			return err
		}
		schnorr, _ = sch.(*curves.ScalarBls12381)
	}

	goodProof := isValidPointG1(proof)
	goodUTick := isValidPointG1(uTick)
	goodComm := isValidPointG2(commitment)
	if goodProof && goodUTick && goodComm && !challenge.IsZero() && !schnorr.IsZero() {
		p.Proof = proof
		p.UTick = uTick
		p.Commitment = commitment
		p.Challenge = challenge
		p.Schnorr = schnorr
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
