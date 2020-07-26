package argon2go

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testHash = "$argon2id$v=19$m=64,t=8,p=4$JsWkGCqBekI$6xyxfM235GUFBm8hCZPufw"

func TestHash(t *testing.T) {
	random = rand.New(rand.NewSource(1337))

	opts := Options{
		Time:       8,
		Memory:     64,
		Threads:    4,
		HashLength: 16,
		SaltLength: 8,
	}

	h, err := Hash([]byte("hunter2"), &opts)
	assert.NoError(t, err)
	assert.Equal(t, testHash, h)
}

func TestVerify(t *testing.T) {
	assert.Equal(t, ErrMismatch, Verify([]byte("hunter1"), testHash))
	assert.Equal(t, ErrInvalid, Verify(nil, "$argon2id$v=18$"))
	assert.NoError(t, Verify([]byte("hunter2"), testHash))
}

func TestParse(t *testing.T) {
	h, s, opts, err := parse(testHash)

	assert.NoError(t, err)
	assert.Equal(t, &Options{8, 64, 4, 16, 8}, opts)
	assert.NotNil(t, h)
	assert.NotNil(t, s)
}
