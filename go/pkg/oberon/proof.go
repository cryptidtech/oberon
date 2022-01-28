package oberon

import (
	"encoding/json"
	"fmt"
	bls12381 "github.com/mikelodder7/bls12-381"
	"io"
)

const proofBytes = 256

type Proof struct {
	Proof, UTick *bls12381.PointG1
	Commitment *bls12381.PointG2
	Challenge, Schnorr *bls12381.Fr
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

	t, err := genRndScalar(rng)
	if err != nil {
		return err
	}
	tt, err := genRndScalar(rng)
	if err != nil {
		return err
	}
	r, err := genRndScalar(rng)
	if err != nil {
		return err
	}
	uTick := g1.MulScalar(g1.New(), u, r)
	points := make([]*bls12381.PointG1, 0, 2+len(blindings))
	scalars := make([]*bls12381.Fr, 0, 2+len(blindings))

	points = append(points, uTick)
	scalars = append(scalars, t)

	points = append(points, token.Value)
	scalars = append(scalars, r)

	for _, b := range blindings {
		points = append(points, b.Value)
		scalars = append(scalars, r)
	}

	proof, err := g1.MultiExp(g1.New(), points, scalars)
	if err != nil {
		return nil
	}

	commitment := g2.MulScalar(g2.New(), g2.One(), t)
	proving := g2.MulScalar(g2.New(), g2.One(), tt)

	challenge, err := hashToScalar([][]byte{
		id,
		g1.ToCompressed(uTick),
		g1.ToCompressed(proof),
		g2.ToCompressed(commitment),
		g2.ToCompressed(proving),
		nonce,
	})
	tv := new(bls12381.Fr)
	tv.Mul(challenge, t)
	schnorr := new(bls12381.Fr)
	schnorr.Sub(tt, tv)

	p.Proof = proof
	p.UTick = uTick
	p.Commitment = commitment
	p.Challenge = challenge
	p.Schnorr = schnorr
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

	proving, err := g2.MultiExp(g2.New(),
		[]*bls12381.PointG2{g2.One(), p.Commitment},
		[]*bls12381.Fr{p.Schnorr, p.Challenge},
	)

	challenge, err := hashToScalar([][]byte{
		id,
		g1.ToCompressed(p.UTick),
		g1.ToCompressed(p.Proof),
		g2.ToCompressed(p.Commitment),
		g2.ToCompressed(proving),
		nonce,
	})
	if err != nil {
		return err
	}
	if challenge == nil || !challenge.Equal(p.Challenge) {
		return fmt.Errorf("invalid challenge")
	}

	rhs, err := g2.MultiExp(g2.New(),
		[]*bls12381.PointG2{pk.W, pk.X, pk.Y, p.Commitment},
		[]*bls12381.Fr{mTick, bls12381.NewFr().One(), m, bls12381.NewFr().One()})
	if err != nil {
		return err
	}
	engine := bls12381.NewEngine()
	engine.AddPairInv(p.UTick, rhs)
	engine.AddPair(p.Proof, genG2)
	if engine.Check() {
		return nil
	} else {
		return fmt.Errorf("check failed")
	}
}

func (p Proof) MarshalBinary() ([]byte, error) {
	var tmp [proofBytes]byte
	copy(tmp[:48], g1.ToCompressed(p.Proof))
	copy(tmp[48:96], g1.ToCompressed(p.UTick))
	copy(tmp[96:192], g2.ToCompressed(p.Commitment))
	copy(tmp[192:224], reverseBytes(p.Challenge.ToBytes()))
	copy(tmp[224:], reverseBytes(p.Schnorr.ToBytes()))
	return tmp[:], nil
}

func (p *Proof) UnmarshalBinary(in []byte) error {
	if len(in) != proofBytes {
		return fmt.Errorf("invalid length")
	}
	proof, err := g1.FromCompressed(in[:48])
	if err != nil {
		return nil
	}
	uTick, err := g1.FromCompressed(in[48:96])
	if err != nil {
		return nil
	}
	commitment, err := g2.FromCompressed(in[96:192])
	if err != nil {
		return nil
	}
	challenge := bls12381.NewFr().FromBytes(reverseBytes(in[192:224]))
	schnorr := bls12381.NewFr().FromBytes(reverseBytes(in[224:]))
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

func (p Proof) MarshalText() ([]byte, error) {
	tmp := map[string][]byte{
		"proof":  g1.ToCompressed(p.Proof),
		"u_tick": g1.ToCompressed(p.UTick),
		"commitment": g2.ToCompressed(p.Commitment),
		"challenge": reverseBytes(p.Challenge.ToBytes()),
		"schnorr": reverseBytes(p.Schnorr.ToBytes()),
	}
	return json.Marshal(&tmp)
}

func (p *Proof) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var proof, uTick *bls12381.PointG1
	var commitment *bls12381.PointG2
	var challenge, schnorr *bls12381.Fr

	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if proofBytes, ok := tmp["proof"]; ok {
		proof, err = g1.FromCompressed(proofBytes)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'proof'")
	}

	if uTickBytes, ok := tmp["u_tick"]; ok {
		uTick, err = g1.FromCompressed(uTickBytes)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'u_tick'")
	}
	if commitmentBytes, ok := tmp["commitment"]; ok {
		commitment, err = g2.FromCompressed(commitmentBytes)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected mak key 'commitment'")
	}
	if challengeBytes, ok := tmp["challenge"]; ok {
		challenge = bls12381.NewFr().FromBytes(reverseBytes(challengeBytes))
	}
	if schnorrBytes, ok := tmp["schnorr"]; ok {
		schnorr = bls12381.NewFr().FromBytes(reverseBytes(schnorrBytes))
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

func genRndScalar(rng io.Reader) (*bls12381.Fr, error) {
	s, e := bls12381.NewFr().Rand(rng)
	if e != nil {
		return nil, e
	}
	for ; s.IsZero() || s.IsOne(); {
		s, e = bls12381.NewFr().Rand(rng)
		if e != nil {
			return nil, e
		}
	}
	return s, nil
}