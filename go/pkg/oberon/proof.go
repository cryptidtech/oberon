package oberon

import (
	"encoding/json"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"io"
)

type Proof struct {
	Proof, UTick *bls12381.PointG1
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
	t, err := hashToScalar([][]byte{id, nonce})
	if err != nil {
		return err
	}
	r, err := bls12381.NewFr().Rand(rng)
	if err != nil {
		return err
	}
	uTick := g1.MulScalar(g1.New(), u, r)
	points := make([]*bls12381.PointG1, 0, 2 + len(blindings))
	scalars := make([]*bls12381.Fr, 0, 2 + len(blindings))

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

	p.Proof = proof
	p.UTick = uTick
	return nil
}

func (p Proof) Open(
	pk *PublicKey,
	id, nonce []byte,
	) error {
	goodProof := isValidPointG1(p.Proof)
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
	t, err := hashToScalar([][]byte{id, nonce})
	if err != nil {
		return err
	}

	rhs, err := g2.MultiExp(g2.New(),
		[]*bls12381.PointG2{pk.W, pk.X, pk.Y, genG2},
		[]*bls12381.Fr{mTick, bls12381.NewFr().One(), m, t})
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
	var tmp [96]byte
	copy(tmp[:48], g1.ToCompressed(p.Proof))
	copy(tmp[48:], g1.ToCompressed(p.UTick))
	return tmp[:], nil
}

func (p *Proof) UnmarshalBinary(in []byte) error {
	if len(in) != 96 {
		return fmt.Errorf("invalid length")
	}
	proof, err := g1.FromCompressed(in[:48])
	if err != nil {
		return nil
	}
	uTick, err := g1.FromCompressed(in[48:])
	if err != nil {
		return nil
	}
	goodProof := isValidPointG1(proof)
	goodUTick := isValidPointG1(uTick)
	if goodProof && goodUTick {
		p.Proof = proof
		p.UTick = uTick
		return nil
	}
	return fmt.Errorf("invalid proof")
}

func (p Proof) MarshalText() ([]byte, error) {
	tmp := map[string][]byte {
		"proof": g1.ToCompressed(p.Proof),
		"u_tick": g1.ToCompressed(p.UTick),
	}
	return json.Marshal(&tmp)
}

func (p *Proof) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var proof, uTick *bls12381.PointG1

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

	goodProof := isValidPointG1(proof)
	goodUTick := isValidPointG1(uTick)
	if goodProof && goodUTick {
		p.Proof = proof
		p.UTick = uTick
		return nil
	}
	return fmt.Errorf("invalid proof")
}
