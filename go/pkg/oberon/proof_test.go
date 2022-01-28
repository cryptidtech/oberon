package oberon

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProof(t *testing.T) {
	// Test values don't use as real world values
	nonce := []byte{138, 162, 3, 91, 76, 34, 240, 157, 149, 94, 93, 228, 214, 51, 50, 136}
	skBytes := []byte{180, 92, 239, 44, 240, 143, 149, 163, 45, 177, 22, 179, 146, 120, 129, 229, 78, 56, 70, 205, 251, 160, 140, 79, 159, 138, 6, 56, 250, 236, 176, 11, 70, 53, 138, 199, 245, 180, 223, 213, 128, 166, 122, 225, 67, 58, 138, 201, 19, 114, 57, 149, 70, 141, 31, 45, 180, 30, 208, 222, 234, 112, 21, 34, 37, 5, 163, 172, 96, 40, 81, 27, 89, 86, 163, 93, 15, 201, 200, 183, 157, 18, 134, 140, 156, 43, 79, 231, 42, 234, 198, 139, 130, 52, 176, 106}
	sk := new(SecretKey)
	err := sk.UnmarshalBinary(skBytes)
	require.NoError(t, err)
	pk := sk.PublicKey()
	require.NotNil(t, pk)

	token, err := NewToken(sk, testId)
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NoError(t, pk.Verify(testId, token))
	blinding, err := NewBlinding([]byte("1234"))
	require.NoError(t, err)
	require.NotNil(t, blinding)

	blindedToken := new(Token).ApplyBlinding(token, blinding)
	proof, err := NewProof(blindedToken, []*Blinding{blinding}, testId, nonce, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.NoError(t, proof.Open(pk, testId, nonce))
	require.Error(t, proof.Open(pk, []byte("wrong id"), nonce))
	require.Error(t, proof.Open(pk, testId, []byte("wrong nonce")))
	// No blindings
	proof, err = NewProof(blindedToken, []*Blinding{}, testId, nonce, crand.Reader)
	require.NoError(t, err)
	require.Error(t, proof.Open(pk, testId, nonce))

	blindedToken = token.ApplyBlinding(token, blinding)
	proof, err = NewProof(blindedToken, []*Blinding{blinding}, testId, nonce, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.NoError(t, proof.Open(pk, testId, nonce))
	require.Error(t, proof.Open(pk, []byte("wrong id"), nonce))
	require.Error(t, proof.Open(pk, testId, []byte("wrong nonce")))
	// No blindings
	proof, err = NewProof(blindedToken, []*Blinding{}, testId, nonce, crand.Reader)
	require.NoError(t, err)
	require.Error(t, proof.Open(pk, testId, nonce))
}

func TestProof2(t *testing.T) {
	id, _ := hex.DecodeString("aa")
	skBytes, _ := hex.DecodeString("b45cef2cf08f95a32db116b3927881e54e3846cdfba08c4f9f8a0638faecb00b46358ac7f5b4dfd580a67ae1433a8ac913723995468d1f2db41ed0deea7015222505a3ac6028511b5956a35d0fc9c8b79d12868c9c2b4fe72aeac68b8234b06a")
	sk := new(SecretKey)
	err := sk.UnmarshalBinary(skBytes)
	require.NoError(t, err)
	nonce, err := hex.DecodeString("8aa2035b4c22f09d955e5de4d6333288")
	require.NoError(t, err)
	tokenBytes, err := hex.DecodeString("8f4c47b8b56cffb091579fb2ded6b946c659b27b97b8d1719897efbd752c4a0af08f471afef1676adb774e631e9cdc34")
	require.NoError(t, err)
	proofBytes, err := hex.DecodeString("a0bb3e92a5cc46c39a5d99f07a824411d82d39d335e8f47890cf0a56ecbafc684f376bba21e74621e66cc70a62eba7da94821448f108612d88ab53af23e7ce98cd2e3d3b1a89acfd700f37d44e1d2eea831c0bf062f0c791a08e0df5a91b1e689173323fd3c0ed7d8e98fd99d607a4d837b5318bde0f7378bb6a6af0701e77987990e6ce9fe26dd5366f3a8cd19bb4bf00878a2ed103db5cc413b3698ee12f8e28d1df2ce597dbccd3b2e37c527ceb4a3346c49b0325625aaed57820fc45c1099c610e4da60a0494c62948e6d22a8d6f1f5112baead3e6c11ce73d56d235770398b17d7b988f837644887cd74825905db6fdc81ae68af1f0c6462c89b3095a24")
	require.NoError(t, err)
	token := new(Token)
	proof := new(Proof)

	err = token.UnmarshalBinary(tokenBytes)
	require.NoError(t, err)

	err = proof.UnmarshalBinary(proofBytes)
	require.NoError(t, err)
	pk := sk.PublicKey()

	require.NoError(t, proof.Open(pk, id, nonce))
}
