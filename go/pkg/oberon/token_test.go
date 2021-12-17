package oberon

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidToken(t *testing.T) {
	skBytes := []byte{180, 92, 239, 44, 240, 143, 149, 163, 45, 177, 22, 179, 146, 120, 129, 229, 78, 56, 70, 205, 251, 160, 140, 79, 159, 138, 6, 56, 250, 236, 176, 11, 70, 53, 138, 199, 245, 180, 223, 213, 128, 166, 122, 225, 67, 58, 138, 201, 19, 114, 57, 149, 70, 141, 31, 45, 180, 30, 208, 222, 234, 112, 21, 34, 37, 5, 163, 172, 96, 40, 81, 27, 89, 86, 163, 93, 15, 201, 200, 183, 157, 18, 134, 140, 156, 43, 79, 231, 42, 234, 198, 139, 130, 52, 176, 106}
	sk := new(SecretKey)
	err := sk.UnmarshalBinary(skBytes)
	require.NoError(t, err)
	pk := sk.PublicKey()

	expToken := []byte{
		174, 221, 77, 7, 147, 66, 236, 180, 112, 106, 14, 104, 35, 123, 13, 189, 211, 158, 32, 194,
		24, 50, 49, 93, 87, 126, 102, 20, 192, 132, 157, 221, 83, 98, 81, 93, 155, 137, 134, 9, 58,
		108, 30, 237, 108, 13, 40, 242,
	}
	token, err := sk.Sign(testId)
	require.NoError(t, err)
	require.Equal(t, expToken, g1.ToCompressed(token.Value))
	require.NoError(t, token.Verify(pk, testId))
	require.Error(t, token.Verify(pk, []byte("wrong identity")))
}
