package oberon

import (
	crand "crypto/rand"
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
