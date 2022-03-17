package oberon

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"golang.org/x/crypto/sha3"
)

var (
	toScalarDst = []byte("OBERON_BLS12381FQ_XOF:SHAKE-256_")
	toCurveDst  = []byte("OBERON_BLS12381G1_XOF:SHAKE-256_SSWU_RO_")
)

func computeM(id []byte) (*curves.ScalarBls12381, error) {
	m, err := hashToScalar([][]byte{id})
	if err != nil {
		return nil, err
	}
	if m.IsZero() {
		return nil, fmt.Errorf("m == 0")
	}
	return m, nil
}

func computeMTick(m *curves.ScalarBls12381) (*curves.ScalarBls12381, error) {
	mTick, err := hashToScalar([][]byte{reverseBytes(m.Bytes())})
	if err != nil {
		return nil, err
	}
	if mTick.IsZero() {
		return nil, fmt.Errorf("m' == 0")
	}
	return mTick, nil
}

func computeU(mTick *curves.ScalarBls12381) (*curves.PointBls12381G1, error) {
	u, err := hashToCurve(reverseBytes(mTick.Bytes()))
	if err != nil {
		return nil, err
	}
	if !isValidPointG1(u) {
		return nil, fmt.Errorf("invalid u")
	}
	return u, nil
}

func hashToCurve(data []byte) (*curves.PointBls12381G1, error) {
	pt := curves.BLS12381G1().NewIdentityPoint().(*curves.PointBls12381G1)
	pt.Value = new(bls12381.G1).Hash(native.EllipticPointHasherShake256(), data, toCurveDst)
	return pt, nil
}

func hashToScalar(data [][]byte) (*curves.ScalarBls12381, error) {
	hasher := sha3.NewShake256()
	n, err := hasher.Write(toScalarDst)
	if err != nil {
		return nil, err
	}
	if n != len(toScalarDst) {
		return nil, fmt.Errorf("unable to write %d bytes", len(toScalarDst))
	}
	for _, d := range data {
		n, err = hasher.Write(d)
		if err != nil {
			return nil, err
		}
		if n != len(d) {
			return nil, fmt.Errorf("unable to write %d bytes", len(data))
		}
	}
	var scalar [48]byte
	n, err = hasher.Read(scalar[:])
	if err != nil {
		return nil, err
	}
	if n != len(scalar) {
		return nil, fmt.Errorf("unable to write %d bytes", len(scalar))
	}

	return fromOkm(scalar[:]), nil
}

func fromOkm(scalar []byte) *curves.ScalarBls12381 {
	var t [64]byte
	copy(t[:48], reverseBytes(scalar))
	value := bls12381.Bls12381FqNew().SetBytesWide(&t)
	sc := curves.BLS12381G1().NewScalar().(*curves.ScalarBls12381)
	sc.Value = value
	return sc
}

func reverseBytes(in []byte) []byte {
	out := make([]byte, len(in))

	for i, j := 0, len(in)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = in[j]
	}

	return out
}

func isValidPointG1(p *curves.PointBls12381G1) bool {
	id := p.Value.IsIdentity()
	// if id == 1 then t == 0
	// if id == 0 then t == 1
	t := -id + 1
	return p.Value.IsOnCurve()&p.Value.InCorrectSubgroup()&t == 1
}

func isValidPointG2(p *curves.PointBls12381G2) bool {
	id := p.Value.IsIdentity()
	// if id == 1 then t == 0
	// if id == 0 then t == 1
	t := -id + 1
	return p.Value.IsOnCurve()&p.Value.InCorrectSubgroup()&t == 1
}
