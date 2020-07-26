package argon2go

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalid is returned when a hash is not syntactically valid.
	ErrInvalid = errors.New("argon2: the hash is not valid")
	// ErrMismatch is returned when hash verification fails.
	ErrMismatch = errors.New("argon2: password did not match the hash")
)

var (
	random = rand.Reader
	prefix = fmt.Sprintf("$argon2id$v=%d$", argon2.Version)
)

var (
	defaults = Options{
		Memory:     2048,
		Time:       4,
		Threads:    4,
		HashLength: 32,
		SaltLength: 16,
	}
)

// Options are the variables used to hash a password.
type Options struct {
	Time       uint32
	Memory     uint32
	Threads    uint8
	HashLength uint32
	SaltLength uint32
}

// Hash applies argon2id hashing using the provided options on the password.
func Hash(password []byte, opts *Options) (string, error) {
	if opts == nil {
		opts = &defaults
	}

	salt := make([]byte, opts.SaltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", err
	}

	return format(hashWithSalt(password, salt, opts), salt, opts), nil
}

// Verify first parses the hash and checks if it is a valid argon2id hash.
// Then it applies the same hashing as in Hash and checks if the password is
// correct.
func Verify(password []byte, hash string) error {
	h, s, opts, err := parse(hash)
	if err != nil {
		return err
	}

	if !bytes.Equal(hashWithSalt(password, s, opts), h) {
		return ErrMismatch
	}

	return nil
}

func hashWithSalt(password, salt []byte, opts *Options) []byte {
	return argon2.IDKey(
		password,
		salt,
		opts.Time,
		opts.Memory,
		opts.Threads,
		opts.HashLength)
}

func format(hash, salt []byte, opts *Options) string {
	return fmt.Sprintf("%sm=%d,t=%d,p=%d$%s$%s",
		prefix,
		opts.Memory,
		opts.Time,
		opts.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

func parse(formatted string) ([]byte, []byte, *Options, error) {
	if !strings.HasPrefix(formatted, prefix) {
		return nil, nil, nil, ErrInvalid
	}

	split := strings.Split(formatted[len(prefix):], "$")
	if len(split) != 3 {
		return nil, nil, nil, ErrInvalid
	}

	var opts Options

	_, err := fmt.Sscanf(split[0], "m=%d,t=%d,p=%d",
		&opts.Memory,
		&opts.Time,
		&opts.Threads)

	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(split[1])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(split[2])
	if err != nil {
		return nil, nil, nil, err
	}

	opts.HashLength = uint32(len(hash))
	opts.SaltLength = uint32(len(salt))

	return hash, salt, &opts, nil
}
