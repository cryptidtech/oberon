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
	expBytes := []byte{132, 134, 52, 39, 104, 194, 25, 230, 216, 42, 0, 63, 34, 54, 107, 231, 82, 166, 247, 224, 33, 36, 218, 239, 81, 144, 152, 175, 106, 143, 129, 6, 122, 192, 119, 97, 255, 119, 247, 135, 208, 177, 81, 210, 179, 111, 141, 72, 32, 87, 81, 207, 39, 39, 24, 91, 125, 206, 144, 53, 124, 67, 100, 86, 107, 124, 135, 14, 83, 6, 145, 211, 0, 7, 82, 131, 174, 107, 136, 56, 235, 54, 81, 165, 243, 235, 216, 215, 95, 164, 31, 48, 118, 118, 67, 37}
	require.Equal(t, 0, bytes.Compare(out, expBytes))
}
