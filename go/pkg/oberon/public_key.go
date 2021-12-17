package oberon

import (
	"encoding/json"
	"fmt"
	bls12381 "github.com/mikelodder7/bls12-381"
)

var (
	g1 = bls12381.NewG1()
	g2 = bls12381.NewG2()
	genG2 = g2.One()
)

type PublicKey struct {
	W *bls12381.PointG2
	X *bls12381.PointG2
	Y *bls12381.PointG2
}

func (p *PublicKey) Verify(id []byte, t *Token) error {
	return t.Verify(p, id)
}

func (p *PublicKey) FromSecretKey(sk *SecretKey) {
	p.W = g2.MulScalar(g2.New(), g2.One(), sk.W)
	p.X = g2.MulScalar(g2.New(), g2.One(), sk.X)
	p.Y = g2.MulScalar(g2.New(), g2.One(), sk.Y)
}

func (p PublicKey) MarshalBinary() ([]byte, error) {
	return append(append(g2.ToCompressed(p.W), g2.ToCompressed(p.X)...), g2.ToCompressed(p.Y)...), nil
}

func (p *PublicKey) UnmarshalBinary(in []byte) error {
	if len(in) != 288 {
		return fmt.Errorf("invalid length")
	}
	w, err := g2.FromCompressed(in[:96])
	if err != nil {
		return err
	}
	x, err := g2.FromCompressed(in[96:192])
	if err != nil {
		return err
	}
	y, err := g2.FromCompressed(in[192:])
	if err != nil {
		return err
	}

	goodW := isValidPointG2(w)
	goodX := isValidPointG2(x)
	goodY := isValidPointG2(y)
	if goodW && goodX && goodY {
		p.W = w
		p.X = x
		p.Y = y
		return nil
	}
	return fmt.Errorf("invalid public key")
}

func (p PublicKey) MarshalText() ([]byte, error) {
	tmp := map[string][]byte {
		"w": g2.ToCompressed(p.W),
		"x": g2.ToCompressed(p.X),
		"y": g2.ToCompressed(p.Y),
	}
	return json.Marshal(&tmp)
}

func (p *PublicKey) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var w, x, y *bls12381.PointG2

	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if wBytes, ok := tmp["w"]; ok {
		w, err = g2.FromCompressed(wBytes)
		if err != nil {
			return nil
		}
	} else {
		return fmt.Errorf("missing expected map key 'w'")
	}

	if xBytes, ok := tmp["x"]; ok {
		x, err = g2.FromCompressed(xBytes)
		if err != nil {
			return nil
		}
	} else {
		return fmt.Errorf("missing expected map key 'x'")
	}

	if yBytes, ok := tmp["y"]; ok {
		y, err = g2.FromCompressed(yBytes)
		if err != nil {
			return nil
		}
	} else {
		return fmt.Errorf("missing expected map key 'y'")
	}

	goodW := isValidPointG2(w)
	goodX := isValidPointG2(x)
	goodY := isValidPointG2(y)

	if goodW && goodX && goodY {
		p.W = w
		p.X = x
		p.Y = y
		return nil
	}
	return fmt.Errorf("invalid secret key")
}

func isValidPointG2(p *bls12381.PointG2) bool {
	return g2.InCorrectSubgroup(p) && g2.IsOnCurve(p) && !g2.IsZero(p)
}