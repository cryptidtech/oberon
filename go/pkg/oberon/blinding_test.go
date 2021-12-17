package oberon

import (
	crand "crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

var testId = []byte("oberon test identity")

func TestBlindingWorks(t *testing.T) {
	blinding := new(Blinding)
	err := blinding.Create([]byte("1234"))
	require.NoError(t, err)

	sk, err := NewSecretKey(crand.Reader)
	require.NoError(t, err)

	token, err := sk.Sign(testId)
	require.NoError(t, err)
	blindedToken := new(Token).ApplyBlinding(token, blinding)
	require.False(t, g1.Equal(token.Value, blindedToken.Value))
	require.True(t, g1.Equal(new(Token).RemoveBlinding(blindedToken, blinding).Value, token.Value))
}