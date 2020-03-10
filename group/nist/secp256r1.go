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
	curve.p = &elliptic.CurveParams{Name: "Secp256r1"}
	curve.p.P, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	curve.p.N, _ = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

	//p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
	//a = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
	//b = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
	//n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
	//h = 01
	//G = 04 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
	//		 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
	curve.p.B, _ = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	curve.p.Gx, _ = new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	curve.p.Gy, _ = new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	curve.p.BitSize = 256
	curve.curveOps = curve
	return curve.curve
}
