package nist

import (
	"crypto/elliptic"
	"math/big"
)

// P256 implements the kyber.Group interface
// for the NIST P-256 elliptic curve,
// based on Go's native elliptic curve library.
type Secp256r1 struct {
	curve
}

func (curve *Secp256r1) String() string {
	return "secp256r1"
}

// Optimized modular square root for P-256 curve, from
// "Mathematical routines for the NIST prime elliptic curves" (April 2010)
func (curve *Secp256r1) sqrt(c *big.Int) *big.Int {
	m := curve.p.P

	t1 := new(big.Int)
	t1.Mul(c, c)
	t1.Mul(t1, c) // t1 = c^(2^2-1)

	p2 := new(big.Int)
	p2.SetBit(p2, 2, 1)
	t2 := new(big.Int)
	t2.Exp(t1, p2, m)
	t2.Mul(t2, t1) // t2 = c^(2^4-1)

	p3 := new(big.Int)
	p3.SetBit(p3, 4, 1)
	t3 := new(big.Int)
	t3.Exp(t2, p3, m)
	t3.Mul(t3, t2) // t3 = c^(2^8-1)

	p4 := new(big.Int)
	p4.SetBit(p4, 8, 1)
	t4 := new(big.Int)
	t4.Exp(t3, p4, m)
	t4.Mul(t4, t3) // t4 = c^(2^16-1)

	p5 := new(big.Int)
	p5.SetBit(p5, 16, 1)
	r := new(big.Int)
	r.Exp(t4, p5, m)
	r.Mul(r, t4) // r = c^(2^32-1)

	p6 := new(big.Int)
	p6.SetBit(p6, 32, 1)
	r.Exp(r, p6, m)
	r.Mul(r, c) // r = c^(2^64-2^32+1)

	p7 := new(big.Int)
	p7.SetBit(p7, 96, 1)
	r.Exp(r, p7, m)
	r.Mul(r, c) // r = c^(2^160-2^128+2^96+1)

	p8 := new(big.Int)
	p8.SetBit(p8, 94, 1)
	r.Exp(r, p8, m)

	// r = c^(2^254-2^222+2^190+2^94) = sqrt(c) mod p256
	return r
}

// Init initializes standard Curve instances
func (curve *Secp256r1) Init() curve {
	curve.curve.Curve = elliptic.P256()
	curve.p = curve.Params()
	curve.p.P, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	curve.p.N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
	curve.p.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	curve.p.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	curve.p.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	curve.p.BitSize = 256
	curve.curveOps = curve
	return curve.curve
}
