package oberon

import (
	"bytes"
	crand "crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSecretKey_MarshalBinary(t *testing.T) {
	testKey, err := NewSecretKey(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, testKey)
	tmp, err := testKey.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, tmp)
	require.Equal(t, 96, len(tmp))
	testKey2 := new(SecretKey)
	err = testKey2.UnmarshalBinary(tmp)
	require.NoError(t, err)
	require.Equal(t, 1, testKey.W.Value.Equal(testKey2.W.Value))
	require.Equal(t, 1, testKey.X.Value.Equal(testKey2.X.Value))
	require.Equal(t, 1, testKey.Y.Value.Equal(testKey2.Y.Value))
}

func TestSecretKey_MarshalText(t *testing.T) {
	testKey, err := NewSecretKey(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, testKey)
	tmp, err := testKey.MarshalText()
	require.NoError(t, err)
	require.NotNil(t, tmp)
	require.Equal(t, 154, len(tmp))
	testKey2 := new(SecretKey)
	err = testKey2.UnmarshalText(tmp)
	require.NoError(t, err)
	require.Equal(t, 1, testKey.W.Value.Equal(testKey2.W.Value))
	require.Equal(t, 1, testKey.X.Value.Equal(testKey2.X.Value))
	require.Equal(t, 1, testKey.Y.Value.Equal(testKey2.Y.Value))
}

func TestSecretKey_UnmarshalBinary(t *testing.T) {
	testKey := []byte{231, 175, 93, 172, 172, 159, 138, 22, 143, 108, 240, 233, 143, 111, 174, 10, 175, 109, 4, 247, 202, 138, 82, 192, 16, 135, 104, 152, 34, 223, 148, 56, 171, 203, 127, 215, 175, 37, 230, 135, 18, 40, 163, 20, 220, 154, 2, 77, 244, 254, 17, 187, 49, 16, 249, 223, 214, 190, 126, 137, 233, 128, 214, 78, 41, 28, 173, 31, 93, 30, 96, 127, 135, 59, 35, 179, 112, 148, 8, 239, 135, 112, 86, 142, 60, 39, 40, 57, 115, 45, 197, 134, 142, 127, 0, 19}
	sk := new(SecretKey)
	err := sk.UnmarshalBinary(testKey)
	require.NoError(t, err)
}

func TestSecretKey_UnmarshalText(t *testing.T) {
	testKey := `{"w":[231,175,93,172,172,159,138,22,143,108,240,233,143,111,174,10,175,109,4,247,202,138,82,192,16,135,104,152,34,223,148,56],"x":[171,203,127,215,175,37,230,135,18,40,163,20,220,154,2,77,244,254,17,187,49,16,249,223,214,190,126,137,233,128,214,78],"y":[41,28,173,31,93,30,96,127,135,59,35,179,112,148,8,239,135,112,86,142,60,39,40,57,115,45,197,134,142,127,0,19]}`
	sk := new(SecretKey)
	err := sk.UnmarshalText([]byte(testKey))
	require.NoError(t, err)
}

func TestHashSecretKey(t *testing.T) {
	var seed [32]byte
	sk, err := HashSecretKey(seed[:])
	require.NoError(t, err)
	out, err := sk.MarshalBinary()
	require.NoError(t, err)
	expBytes := []byte{6, 129, 143, 106, 175, 152, 144, 81, 239, 218, 36, 33, 224, 247, 166, 82, 231, 107, 54, 34, 63, 0, 42, 216, 230, 25, 194, 104, 39, 52, 134, 132, 86, 100, 67, 124, 53, 144, 206, 125, 91, 24, 39, 39, 207, 81, 87, 32, 72, 141, 111, 179, 210, 81, 177, 208, 135, 247, 119, 255, 97, 119, 192, 122, 37, 67, 118, 118, 48, 31, 164, 95, 215, 216, 235, 243, 165, 81, 54, 235, 56, 136, 107, 174, 131, 82, 7, 0, 211, 145, 6, 83, 14, 135, 124, 107}
	require.Equal(t, 0, bytes.Compare(out, expBytes))
}
