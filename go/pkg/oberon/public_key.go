package oberon

import (
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type PublicKey struct {
	W *curves.PointBls12381G2
	X *curves.PointBls12381G2
	Y *curves.PointBls12381G2
}

func (p *PublicKey) Verify(id []byte, t *Token) error {
	return t.Verify(p, id)
}

func (p *PublicKey) FromSecretKey(sk *SecretKey) {
	curve := curves.BLS12381G2()
	p.W, _ = curve.ScalarBaseMult(sk.W).(*curves.PointBls12381G2)
	p.X, _ = curve.ScalarBaseMult(sk.X).(*curves.PointBls12381G2)
	p.Y, _ = curve.ScalarBaseMult(sk.Y).(*curves.PointBls12381G2)
}

func (p PublicKey) MarshalBinary() ([]byte, error) {
	return append(append(p.W.ToAffineCompressed(), p.X.ToAffineCompressed()...), p.Y.ToAffineCompressed()...), nil
}

func (p *PublicKey) UnmarshalBinary(in []byte) error {
	if len(in) != 288 {
		return fmt.Errorf("invalid length")
	}
	curve := curves.BLS12381G2()
	w, err := curve.Point.FromAffineCompressed(in[:96])
	if err != nil {
		return err
	}
	x, err := curve.Point.FromAffineCompressed(in[96:192])
	if err != nil {
		return err
	}
	y, err := curve.Point.FromAffineCompressed(in[192:])
	if err != nil {
		return err
	}

	W, _ := w.(*curves.PointBls12381G2)
	X, _ := x.(*curves.PointBls12381G2)
	Y, _ := y.(*curves.PointBls12381G2)

	goodW := !w.IsIdentity()
	goodX := !x.IsIdentity()
	goodY := !y.IsIdentity()

	if goodW && goodX && goodY {
		p.W = W
		p.X = X
		p.Y = Y
		return nil
	}
	return fmt.Errorf("invalid public key")
}

func (p PublicKey) MarshalText() ([]byte, error) {
	tmp := map[string][]byte{
		"w": p.W.ToAffineCompressed(),
		"x": p.X.ToAffineCompressed(),
		"y": p.Y.ToAffineCompressed(),
	}
	return json.Marshal(&tmp)
}

func (p *PublicKey) UnmarshalText(in []byte) error {
	var tmp map[string][]byte
	var w, x, y curves.Point

	curve := curves.BLS12381G2()
	err := json.Unmarshal(in, &tmp)
	if err != nil {
		return err
	}
	if wBytes, ok := tmp["w"]; ok {
		w, err = curve.NewIdentityPoint().FromAffineCompressed(wBytes)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'w'")
	}

	if xBytes, ok := tmp["x"]; ok {
		x, err = curve.NewIdentityPoint().FromAffineCompressed(xBytes)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'x'")
	}

	if yBytes, ok := tmp["y"]; ok {
		y, err = curve.NewIdentityPoint().FromAffineCompressed(yBytes)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing expected map key 'y'")
	}

	W, _ := w.(*curves.PointBls12381G2)
	X, _ := x.(*curves.PointBls12381G2)
	Y, _ := y.(*curves.PointBls12381G2)

	goodW := !w.IsIdentity()
	goodX := !x.IsIdentity()
	goodY := !y.IsIdentity()

	if goodW && goodX && goodY {
		p.W = W
		p.X = X
		p.Y = Y
		return nil
	}
	return fmt.Errorf("invalid secret key")
}
