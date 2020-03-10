package nist

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/michaljirman/kyber"
	"github.com/michaljirman/kyber/group/internal/marshalling"
	"github.com/michaljirman/kyber/util/random"
	"github.com/michaljirman/kyber/xof/blake2xb"
	"go.dedis.ch/fixbuf"
)

// Suite128 is the suite for P256 curve
type Suite128 struct {
	p256
}

// Hash returns the instance associated with the suite
func (s *Suite128) Hash() hash.Hash {
	return sha256.New()
}

// XOF creates the XOF associated with the suite
func (s *Suite128) XOF(key []byte) kyber.XOF {
	return blake2xb.New(key)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *Suite128) RandomStream() cipher.Stream {
	return random.New()
}

func (s *Suite128) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *Suite128) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.encoding interface
func (s *Suite128) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// NewBlakeSHA256P256 returns a cipher suite based on package
// github.com/michaljirman/kyber/v3/xof/blake2xb, SHA-256, and the NIST P-256
// elliptic curve. It returns random streams from Go's crypto/rand.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256P256() *Suite128 {
	suite := new(Suite128)
	suite.p256.Init()
	return suite
}

// Suite129 is the suite for secp256r1 curve
type Suite129 struct {
	Secp256r1
}

// Hash returns the instance associated with the suite
func (s *Suite129) Hash() hash.Hash {
	return sha256.New()
}

// XOF creates the XOF associated with the suite
func (s *Suite129) XOF(key []byte) kyber.XOF {
	return blake2xb.New(key)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *Suite129) RandomStream() cipher.Stream {
	return random.New()
}

func (s *Suite129) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *Suite129) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.encoding interface
func (s *Suite129) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

func NewSecp256r1() *Suite129 {
	suite := new(Suite129)
	suite.Secp256r1.Init()
	return suite
}
