package twoecdsa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
)

// priv := new(ecdsa.PrivateKey)
// s.X = Rand(priv.Curve)
func Rand() *big.Int {
	c := crypto.S256()
	n := c.Params().N
	for {
		k, _ := rand.Int(rand.Reader, big.NewInt(1000000000000000000))
		if k.Sign() != 0 && k.Cmp(n) < 0 {
			return k
		}
		fmt.Println("priv.Ka")
	}
}

var q3 = big.NewInt(0).Div(secp256k1.GetSecp256k1().GetN(), big.NewInt(3))
var d_q3 = big.NewInt(0).Div(big.NewInt(0).Mul(secp256k1.GetSecp256k1().GetN(), big.NewInt(2)), big.NewInt(3))

type PartyA struct {
	///pkey
	prv *big.Int
	///ecdsa
	r    *big.Int
	R    *point.Point
	Qpub *point.Point
	Qa   *point.Point
	Ra   *point.Point
	//paillier
	paillierKey *paillier.PrivateKey
	pk          *paillier.PublicKey
	p           *big.Int
	q           *big.Int
	N           *big.Int
	ckey        *big.Int
	///
}

var private_key1 = "df1a627fd5ec89eaed03fd1ab246c414b8e8d57538d330e8a281137c75b88d36"
var private_key2 = "0ac7d64995c6b4daac2688c0e40d25af50887ada5b7a4cbe197ada0bdef32375"
var public_key = "045ae6d14d4934eeb004b818d687a1ea6efff0946d043dfb9338c0601a1ae0387fd00bfcefeff11961a48edc66f62ad87feed8a9ef157efa294c91466c70039bbe"

// x1 => [q/3, 2q/3]
// commit: Q1 R1
func NewPartyA() *PartyA {
	x1 := big.NewInt(0)
	for {
		r, err := rand.Int(rand.Reader, d_q3)
		if err != nil {
			panic(err)
		}
		if r.Cmp(q3) == 1 {
			continue
		}
		x1 = r
		break
	}
	x1, ok := big.NewInt(0).SetString(private_key1, 16)
	if !ok {
		panic(errors.New("private_key1"))
	}
	///
	Q := secp256k1.GetSecp256k1().GetG().ScalarMul(x1)
	// r, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	// if err != nil {
	// 	panic(err)
	// }
	r := Rand()
	// r := big.NewInt(545385580002207433)
	R := secp256k1.GetSecp256k1().GetG().ScalarMul(r)
	////
	sk, pk, err := paillier.GenerateKeyPair(context.Background(), 1024)
	if err != nil {
		panic(err)
	}
	ckey, err := pk.Encrypt(x1)
	if err != nil {
		panic(err)
	}

	return &PartyA{
		prv:         x1,
		r:           r,
		Qa:          Q,
		Ra:          R,
		paillierKey: sk,
		pk:          pk,

		ckey: ckey,
	}
}
func (p *PartyA) Sign(signaturepartial *big.Int, mhash []byte) []byte {
	sdc, err := p.paillierKey.Decrypt(signaturepartial)
	if err != nil {
		panic(err)
	}
	///
	dc := new(big.Int).Mod(
		sdc,
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("sdc:", sdc.Text(16))
	fmt.Println("dc:", dc.Text(16))
	///
	k1_inv := new(big.Int).ModInverse(p.r, secp256k1.GetSecp256k1().GetN())
	//ss = k1_inv * signaturepartial mod q
	s := new(big.Int).Mod(
		new(big.Int).Mul(k1_inv, dc),
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("signs:", s.Text(16))
	signs := s
	// subs := new(big.Int).Sub(secp256k1.GetSecp256k1().GetN(), s)
	// fmt.Println("signssubs:", subs.Text(16))
	// signs := big.NewInt(0)
	// if s.Cmp(subs) < 0 {
	// 	signs = s
	// } else {
	// 	signs = subs
	// }
	// // ///
	// if signs.Cmp(secp256k1halfN) > 0 {
	// 	fmt.Println("secp256k1halfN")
	// }
	////
	signr := new(big.Int).Mod(p.R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN())
	///
	signv := 28
	if p.R.GetY().GetNum().Bit(0) == 0 {
		signv = 27
	} else {
		signv = 28
	}
	///
	sign := RecoverPlain(signr, signs, big.NewInt(int64(signv)), false)
	return sign
}
func (p *PartyA) ZKProof() (*point.Point, *point.Point) {
	return p.Qa, p.Ra
}
func (p *PartyA) PaillierProof() (*big.Int, *big.Int) {
	// //(R_1 = g^{r_1} mod n^2)，这里 (g = n + 1\。
	// r1, _ := rand.Int(rand.Reader, p.paillierKey.N)
	// g := new(big.Int).Add(p.paillierKey.N, big.NewInt(1))
	// R1 := new(big.Int).Exp(g, r1, p.paillierKey.NSquare())
	// ////
	// hash := sha256.New()
	// hash.Write(R1.Bytes())
	// hash.Write(p.paillierKey.PublicKey.N.Bytes())
	// cbytes := hash.Sum(nil)
	// c := new(big.Int).SetBytes(cbytes)
	// ///(s_1 = r_1 + c dot lambda mod varphi(n))
	// s1 := new(big.Int).Add(r1, new(big.Int).Mul(c, p.paillierKey.LambdaN))
	// s1 = s1.Mod(s1, p.paillierKey.PhiN)
	// return R1, s1
	// 生成随机数 r1
	r1, err := rand.Int(rand.Reader, p.paillierKey.PhiN) // 随机数范围应为 phi(n²)
	if err != nil {
		panic(err)
	}
	g := new(big.Int).Add(p.paillierKey.N, big.NewInt(1))
	y := p.paillierKey.N // 生成元 y = N
	// 正确承诺：R1 = g^r1 * y^x mod n²
	R1 := new(big.Int).Exp(g, r1, p.paillierKey.NSquare())
	R1 = new(big.Int).Mul(R1, new(big.Int).Exp(y, p.paillierKey.PhiN, p.paillierKey.NSquare()))
	R1 = R1.Mod(R1, p.paillierKey.NSquare())
	hash := sha256.New()
	hash.Write(R1.Bytes())
	hash.Write(p.paillierKey.PublicKey.N.Bytes())
	c := new(big.Int).SetBytes(hash.Sum(nil))
	c = c.Mod(c, p.paillierKey.PhiN) // 挑战值模 phi(n²)

	s1 := new(big.Int).Add(r1, new(big.Int).Mul(c, p.paillierKey.PhiN))
	s1 = s1.Mod(s1, p.paillierKey.PhiN)
	return R1, s1
}

//  (s = r + c * x_1 mod q)
func (p *PartyA) Challange(c *big.Int, Qb *point.Point, Rb *point.Point) *big.Int {
	p.Qpub = Qb.ScalarMul(p.prv)
	r := Rb.ScalarMul(p.r)
	p.R = r
	return new(big.Int).Mod(new(big.Int).Add(p.r, new(big.Int).Mul(c, p.prv)), secp256k1.GetSecp256k1().GetN())
}
func (p *PartyA) CKey() *big.Int {
	return p.ckey
}

type PartyB struct {
	prv *big.Int
	///ecsd
	r    *big.Int
	Qb   *point.Point
	Rb   *point.Point
	R    *point.Point
	Qpub *point.Point
	Qa   *point.Point
	Ra   *point.Point
	c    *big.Int
	///
	///
	ckey        *big.Int
	paillierPub *paillier.PublicKey
	paillierQ1  *point.Point
	//
}

func NewPartyB() *PartyB {
	// x2, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	// if err != nil {
	// 	panic(err)
	// }
	x2, ok := big.NewInt(0).SetString(private_key2, 16)
	if !ok {
		panic(errors.New("private_key1"))
	}
	///
	Q := secp256k1.GetSecp256k1().GetG().ScalarMul(x2)
	// r, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	// if err != nil {
	// 	panic(err)
	// }
	// r := big.NewInt(7)
	r := Rand()
	// r := big.NewInt(32531902837695157)
	R := secp256k1.GetSecp256k1().GetG().ScalarMul(r)

	return &PartyB{
		prv: x2,
		Qb:  Q,
		Rb:  R,
		r:   r,
	}
}
func (p *PartyB) RecvCommit(Qa *point.Point, Ra *point.Point) *big.Int {
	p.Qa = Qa
	p.Ra = Ra
	c, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	if err != nil {
		panic(err)
	}
	///
	r := Ra.ScalarMul(p.r)
	p.R = r
	p.Qpub = Qa.ScalarMul(p.prv)
	p.c = c
	return c
}

// /verify
// / left: s * G
// right: R + c * Q1
// if left == right => ok
func (p *PartyB) Verify(response *big.Int) bool {
	left := secp256k1.GetSecp256k1().GetG().ScalarMul(response)
	right := p.Ra.Add(p.Qa.ScalarMul(p.c))
	if left.Equal(right) {
		return true
	}
	return false
}

func (p *PartyB) SignaturePartial(hash []byte) *big.Int {
	//(c_1 ={Enc}_{pk}(p * q + (k_2^{-1} * H(m) mod q); {r}))
	// c1 = Enc (1 + (p*q + (k2_inv * m mod q)) * N) * r^N mod N^2

	// r, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	// if err != nil {
	// 	panic(err)
	// }
	// N2 := new(big.Int).Exp(secp256k1.GetSecp256k1().GetN(), big.NewInt(2), nil)
	// rr, err := rand.Int(rand.Reader, N2)
	// if err != nil {
	// 	panic(err)
	// }

	k2_inv := new(big.Int).ModInverse(p.r, secp256k1.GetSecp256k1().GetN())
	c := new(big.Int).Mod(
		new(big.Int).Mul(k2_inv, new(big.Int).SetBytes(hash)),
		secp256k1.GetSecp256k1().GetN())
	c1, err := p.paillierPub.Encrypt(c)
	if err != nil {
		fmt.Println(err)
	}
	//c1 = (1 + c1 * N) * r mod N^2
	////
	//(v = k_inv {-1} * r * x_2 mod q)
	rx := new(big.Int).Mod(
		p.R.GetX().GetNum(),
		secp256k1.GetSecp256k1().GetN(),
	)
	k2invr := new(big.Int).Mod(new(big.Int).Mul(k2_inv, rx), secp256k1.GetSecp256k1().GetN())
	k2invrp := new(big.Int).Mul(k2invr, p.prv)
	v := new(big.Int).Mod(k2invrp, secp256k1.GetSecp256k1().GetN())
	// v := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(k2_inv, r), p.r), secp256k1.GetSecp256k1().GetN())
	//(c_2 = v omuls ckey)
	c2, err := p.paillierPub.HomoMult(v, p.ckey)
	if err != nil {
		fmt.Println(err)
	}
	//(c_3 = c_1 oplus c_2)
	c3, err := p.paillierPub.HomoAdd(c1, c2)
	if err != nil {
		panic(err)
	}

	return c3
}

// func (p *PartyB) PaillierVerify(pub *paillier.PublicKey, R1, s1 *big.Int) bool {
// 	// // (c' = H(R_1 || pk))。
// 	// ////
// 	// hash := sha256.New()
// 	// hash.Write(R1.Bytes())
// 	// hash.Write(pub.N.Bytes())
// 	// cbytes := hash.Sum(nil)
// 	// c := new(big.Int).SetBytes(cbytes)
// 	// ///
// 	// g := new(big.Int).Add(pub.N, big.NewInt(1))
// 	// ///g^s1
// 	// left := new(big.Int).Exp(g, s1, pub.NSquare())
// 	// // right = R1 * (N^c) mod n^2
// 	// rparty := new(big.Int).Exp(pub.N, c, pub.NSquare())
// 	// right := new(big.Int).Mul(R1, rparty)
// 	// ///left equiv right mod n^2
// 	// right = right.Mod(right, pub.NSquare())
// 	// if left.Cmp(right) == 0 {
// 	// 	return true
// 	// }
// 	// return false

// 	g := new(big.Int).Add(pub.N, big.NewInt(1))
// 	y := pub.N // 生成元 y = N

// 	hash := sha256.New()
// 	hash.Write(R1.Bytes())
// 	hash.Write(pub.N.Bytes())
// 	c := new(big.Int).SetBytes(hash.Sum(nil))
// 	c = c.Mod(c, new(big.Int).Mul(pub.N, new(big.Int).Sub(pub.N, big.NewInt(1)))) // phi(n²) = n*phi(n)

// 	// 正确验证式：g^s1 ≡ R1 * y^c mod n²
// 	left := new(big.Int).Exp(g, s1, pub.NSquare())
// 	right := new(big.Int).Mul(R1, new(big.Int).Exp(y, c, pub.NSquare()))
// 	right = right.Mod(right, pub.NSquare())

// 	return left.Cmp(right) == 0
// }

type QParty struct {
	X, Y *big.Int
}
type Request struct {
	X, Y *big.Int
	PKey *paillier.PrivateKey
	Q    *QParty
	E1   []byte
}

func (s *Request) Marshal() ([]byte, error) {
	j, err := json.Marshal(s)
	return j, err
}
func (s *Request) Unmarshal(j []byte) error {
	return json.Unmarshal(j, s)
}

// signature_partial = encrypt(random * order + k2_inv * msg) |+| encrypt(k1) |*| (k2_inv * rx * k2)/
// //s = (k1*k2)-1 * (H(m)+r*(x1+x2)) mod q
// /(k2-1 * H(m)+r*k2-1 * (x2 + x1)) * k1-1 mod q
// /
// /E(x1) ->
// c1= E(p q)+k2-1*H(m)
// c2 = E(x2) + E(x1)
// c4 = r*k2-1 * c3
// c5 = c1+c4
// D(c5)*k1-1
// func (s *Party) SignParty(hash []byte) []byte {
// 	k_Inv := new(big.Int).ModInverse(s.k, s.prv.Curve.Params().N)
// 	e := hashToInt(hash, s.prv.Curve)
// 	c1 := new(big.Int).Mul(k_Inv, e)
// 	//
// 	c2, err := paillier.Encrypt(&s.reqeust.PKey.PublicKey, s.prv.D.Bytes())
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	c3 := AddCipher(&s.reqeust.PKey.PublicKey, s.reqeust.E1, c2)
// 	///
// 	b4 := new(big.Int).Mul(s.r, k_Inv)
// 	c4 := paillier.Mul(&s.reqeust.PKey.PublicKey, c3, b4.Bytes())

// 	c5, _ := paillier.Add(&s.reqeust.PKey.PublicKey, c4, c1.Bytes())
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	///
// 	return c5
// }
// func (s *Party) Sign(hash []byte, c []byte, r *big.Int) []byte {
// 	k_Inv := new(big.Int).ModInverse(s.k, s.prv.Curve.Params().N)
// 	d, err := paillier.Decrypt(s.reqeust.PKey, c)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	ss := new(big.Int).Mul(new(big.Int).SetBytes(d), k_Inv)
// 	sigs := new(big.Int).Set(s.prv.Curve.Params().N)
// 	ss = ss.Mod(ss, s.prv.Curve.Params().N)
// 	sigs.Sub(sigs, ss)
// 	if ss.Cmp(sigs) < 0 {
// 		sigs = ss
// 	}
// 	if sigs.Sign() <= 0 {
// 		// ss = ss.Neg(ss)
// 		fmt.Println("ss is negative")
// 	}
// 	if r.Sign() <= 0 {
// 		fmt.Println("r is negative")
// 	}

//		///v
//		overflow := 0
//		pubKeyRecoveryCode := byte(0)
//		if r.Cmp(secp256k1N) != -1 {
//			overflow = 1
//		}
//		if r.Cmp(common.Big1) < 0 {
//			fmt.Println("r < 0")
//		}
//		if ss.Cmp(common.Big1) < 0 {
//			fmt.Println("ss < 0")
//		}
//		fmt.Println(secp256k1N)
//		fmt.Println(s.prv.Curve.Params().N)
//		recoveryCode := byte(overflow<<1) | byte(s.reqeust.Y.Bit(0)&1)
//		if ss.Cmp(secp256k1halfN) > 0 {
//			// ss = ss.Neg(ss)
//			ss.Sub(ss, s.prv.Curve.Params().N)
//			ss.Mod(ss, s.prv.Curve.Params().N)
//			// recoveryCode ^= 0x01
//			fmt.Println("ss is secp256k1halfN")
//		}
//		pubKeyRecoveryCode = recoveryCode
//		pubKeyRecoveryCode += 27
//		sign := RecoverPlain(r, ss, big.NewInt(0).SetBytes([]byte{pubKeyRecoveryCode}), false)
//		return sign[:len(sign)-1]
//	}
func (p *PartyA) PaillierResponse(alpha *big.Int) *point.Point {
	// \(Q' = \alpha \cdot G\)
	x1, err := p.paillierKey.Decrypt(alpha)
	if err != nil {
		panic(err)
	}
	Q1 := secp256k1.GetSecp256k1().GetG().ScalarMul(x1)
	return Q1
}
func (p *PartyB) PaillierChanllenge(pub *paillier.PublicKey, ckey *big.Int) (*big.Int, *point.Point) {

	// alpha, err := pub.HomoMult(big.NewInt(2), ckey)
	// if err != nil {
	// 	panic(err)
	// }
	// c1, _ := pub.Encrypt(big.NewInt(1))
	// alpha, err = pub.HomoAdd(c1, alpha)
	// if err != nil {
	// 	panic(err)
	// }
	// return alpha, nil

	//\(\alpha = a \cdot x_1 + b\)
	a, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	if err != nil {
		panic(err)
	}
	b, err := rand.Int(rand.Reader, secp256k1.GetSecp256k1().GetN())
	if err != nil {
		panic(err)
	}
	c1, err := pub.HomoMult(a, ckey)
	if err != nil {
		panic(err)
	}
	c2, err := pub.Encrypt(b)
	if err != nil {
		panic(err)
	}
	s, err := pub.HomoAdd(c1, c2)
	if err != nil {
		panic(err)
	}
	///\(Q' = a \cdot Q_1 + b \cdot G\)

	Q1 := p.Qa.ScalarMul(a).Add(secp256k1.GetSecp256k1().GetG().ScalarMul(b))
	p.paillierQ1 = Q1
	p.ckey = ckey
	p.paillierPub = pub
	return s, Q1
}
func (p *PartyB) PaillierVerify(Q1 *point.Point) bool {
	// fmt.Println("Q1:", Q1.Print())
	// fmt.Println("p.Q1:", p.paillierQ1.Print())
	if Q1.Equal(p.paillierQ1) {
		return true
	}
	return false
}

///
