package dkg

import (
	"bytes"
	"encoding/binary"

	"github.com/michaljirman/kyber"
	"github.com/michaljirman/kyber/share"
	vss "github.com/michaljirman/kyber/share/vss/pedersen"
)

// DistKeyShare holds the share of a distributed key for a participant.
type DistKeyShare struct {
	// Coefficients of the public polynomial holding the public key.
	Commits []kyber.Point
	// Share of the distributed secret which is private information.
	Share *share.PriShare
	// Coefficients of the private polynomial generated by the node holding the
	// share. The final distributed polynomial is the sum of all these
	// individual polynomials, but it is never computed.
	PrivatePoly []kyber.Scalar
}

// Public returns the public key associated with the distributed private key.
func (d *DistKeyShare) Public() kyber.Point {
	return d.Commits[0]
}

// PriShare implements the dss.DistKeyShare interface so either pedersen or
// rabin dkg can be used with dss.
func (d *DistKeyShare) PriShare() *share.PriShare {
	return d.Share
}

// Commitments implements the dss.DistKeyShare interface so either pedersen or
// rabin dkg can be used with dss.
func (d *DistKeyShare) Commitments() []kyber.Point {
	return d.Commits
}

// Deal holds the Deal for one participant as well as the index of the issuing
// Dealer.
type Deal struct {
	// Index of the Dealer in the list of participants
	Index uint32
	// Deal issued for another participant
	Deal *vss.EncryptedDeal
	// Signature over the whole message
	Signature []byte
}

// MarshalBinary returns a binary representation of this deal, which is the
// message  signed in a dkg deal.
func (d *Deal) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, d.Index)
	b.Write(d.Deal.Cipher)
	return b.Bytes(), nil
}

// Response holds the Response from another participant as well as the index of
// the target Dealer.
type Response struct {
	// Index of the Dealer for which this response is for
	Index uint32
	// Response issued from another participant
	Response *vss.Response
}

// Justification holds the Justification from a Dealer as well as the index of
// the Dealer in question.
type Justification struct {
	// Index of the Dealer who answered with this Justification
	Index uint32
	// Justification issued from the Dealer
	Justification *vss.Justification
}
