package oberon

import (
	"encoding/binary"
	"fmt"
	bls12381 "github.com/mikelodder7/bls12-381"
	"golang.org/x/crypto/sha3"
)

var (
	f2192       = &bls12381.Fr{0, 0, 0, 1}
	toScalarDst = []byte("OBERON_BLS12381FQ_XOF:SHAKE-256_")
	toCurveDst  = []byte("OBERON_BLS12381G1_XOF:SHAKE-256_SSWU_RO_")
)

func computeM(id []byte) (*bls12381.Fr, error) {
	m, err := hashToScalar([][]byte{id})
	if err != nil {
		return nil, err
	}
	if m.IsZero() {
		return nil, fmt.Errorf("m == 0")
	}
	return m, nil
}

func computeMTick(m *bls12381.Fr) (*bls12381.Fr, error) {
	mTick, err := hashToScalar([][]byte{reverseBytes(m.ToBytes())})
	if err != nil {
		return nil, err
	}
	if mTick.IsZero() {
		return nil, fmt.Errorf("m' == 0")
	}
	return mTick, nil
}

func computeU(mTick *bls12381.Fr) (*bls12381.PointG1, error) {
	u, err := hashToCurve(reverseBytes(mTick.ToBytes()))
	if err != nil {
		return nil, err
	}
	if !isValidPointG1(u) {
		return nil, fmt.Errorf("invalid u")
	}
	return u, nil
}

func hashToCurve(data []byte) (*bls12381.PointG1, error) {
	return g1.HashToCurve(bls12381.HashToFpXOFSHAKE256, data, toCurveDst)
}

func hashToScalar(data [][]byte) (*bls12381.Fr, error) {
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

func fromOkm(scalar []byte) *bls12381.Fr {
	d0 := &bls12381.Fr{
		binary.BigEndian.Uint64(scalar[16:24]),
		binary.BigEndian.Uint64(scalar[8:16]),
		binary.BigEndian.Uint64(scalar[:8]),
		0,
	}
	d1 := &bls12381.Fr{
		binary.BigEndian.Uint64(scalar[40:48]),
		binary.BigEndian.Uint64(scalar[32:40]),
		binary.BigEndian.Uint64(scalar[24:32]),
		0,
	}
	sc := bls12381.NewFr()
	sc.Mul(d0, f2192)
	sc.Add(sc, d1)
	return sc
}

func reverseBytes(in []byte) []byte {
	out := make([]byte, len(in))

	for i, j := 0, len(in)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = in[j]
	}

	return out
}

func isValidPointG1(p *bls12381.PointG1) bool {
	return g1.InCorrectSubgroup(p) && g1.IsOnCurve(p) && !g1.IsZero(p)
}
