package twoecdsa

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
)

func Test_partyRand(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	Qa, Ra := partya.ZKProof()
	c := partyb.RecvCommit(Qa, Ra)
	s := partya.Challange(c, partyb.Qb, partyb.Rb)
	if partyb.Verify(s) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}

	R1 := secp256k1.GetSecp256k1().GetG().ScalarMul(partya.r)
	R2 := secp256k1.GetSecp256k1().GetG().ScalarMul(partyb.r)

	fmt.Println("R1:", new(big.Int).Mod(R1.GetX().GetNum(), secp256k1.GetSecp256k1().GetN()))
	fmt.Println("R2:", new(big.Int).Mod(R2.GetX().GetNum(), secp256k1.GetSecp256k1().GetN()))
	///
	R := R2.ScalarMul(partya.r)
	fmt.Println("R:", new(big.Int).Mod(R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN()).Text(16))
	// R1: 53555801739432996128028460565229477341548639420045108894362957301991437066674
	// R2: 9890201626946227849029853854641843197084658513977574962286305285053946738632
	// R: 41937088646828571960376309329733847653566299828814404895028369638044203343356
	// 5cb78d0f81e513b3b2fa9a3882b75166dab95d935a2361a9857387242485ddfc
}

func Test_pub(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	Qa, Ra := partya.ZKProof()
	c := partyb.RecvCommit(Qa, Ra)
	s := partya.Challange(c, partyb.Qb, partyb.Rb)
	if partyb.Verify(s) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}
	pubkey := ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     partya.Qpub.GetX().GetNum(),
		Y:     partya.Qpub.GetY().GetNum(),
	}

	fmt.Println("pria:", common.Bytes2Hex(partya.prv.Bytes()))
	fmt.Println("prib:", common.Bytes2Hex(partyb.prv.Bytes()))
	prv := new(big.Int).Mod(
		new(big.Int).Mul(partya.prv, partyb.prv),
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("prv:", prv)
	fmt.Println("prv:", prv.Text(16))
	fmt.Println("pub:", public_key)
	fmt.Println("pub:", common.Bytes2Hex(crypto.FromECDSAPub(&pubkey)))
	// pria: df1a627fd5ec89eaed03fd1ab246c414b8e8d57538d330e8a281137c75b88d36
	// prib: 0ac7d64995c6b4daac2688c0e40d25af50887ada5b7a4cbe197ada0bdef32375
	// prv: d2ef579ddbc61c9c639e480c8736535869eb66b3d6ecd2d8ebeff78b021ffcb6
	// prv: 115792089237316195423570985008687907852837564279074904382605163141518161494337
	// pub: 045ae6d14d4934eeb004b818d687a1ea6efff0946d043dfb9338c0601a1ae0387fd00bfcefeff11961a48edc66f62ad87feed8a9ef157efa294c91466c70039bbe
	// pub: 045ae6d14d4934eeb004b818d687a1ea6efff0946d043dfb9338c0601a1ae0387fd00bfcefeff11961a48edc66f62ad87feed8a9ef157efa294c91466c70039bbe
	////
	prvkey, err := crypto.ToECDSA(prv.Bytes())
	if err != nil {
		panic(err)
	}
	pubbytes := crypto.FromECDSAPub(&prvkey.PublicKey)
	fmt.Println("public:", common.Bytes2Hex(pubbytes))
	///
	msg := "hello world"
	hash := crypto.Keccak256Hash([]byte(msg))
	sign, err := crypto.Sign(hash.Bytes(), prvkey)
	if err != nil {
		panic(err)
	}
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), sign)
	fmt.Println("sigPublicKey:", common.Bytes2Hex(sigPublicKey))
	////
}
func Test_k(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	Qa, Ra := partya.ZKProof()
	c := partyb.RecvCommit(Qa, Ra)
	s := partya.Challange(c, partyb.Qb, partyb.Rb)
	if partyb.Verify(s) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}
	///
	fmt.Println("partya k:", partya.r.String())
	fmt.Println("partyb k:", partyb.r.String())
	k := new(big.Int).Mul(partya.r, partyb.r)
	fmt.Println("K:", k.String())
	R := secp256k1.GetSecp256k1().GetG().ScalarMul(k)
	Rx := new(big.Int).Mod(
		R.GetX().GetNum(),
		secp256k1.GetSecp256k1().GetN(),
	)
	///
	// R: 41937088646828571960376309329733847653566299828814404895028369638044203343356
	// 5cb78d0f81e513b3b2fa9a3882b75166dab95d935a2361a9857387242485ddfc
	fmt.Println("R:", Rx.Text(16))
	//
	// crypto.Sign()
}
func Test_comsign(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	Qa, Ra := partya.ZKProof()
	c := partyb.RecvCommit(Qa, Ra)
	s := partya.Challange(c, partyb.Qb, partyb.Rb)
	if partyb.Verify(s) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}
	///
	fmt.Println("partya prv:", partya.prv.String())
	fmt.Println("partyb prv:", partyb.prv.String())
	fmt.Println("partya k:", partya.r.String())
	fmt.Println("partyb k:", partyb.r.String())
	k := new(big.Int).Mul(partya.r, partyb.r)
	fmt.Println("K:", k.String())
	R := secp256k1.GetSecp256k1().GetG().ScalarMul(k)
	Rx := new(big.Int).Mod(
		R.GetX().GetNum(),
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("R:", Rx.Text(16))
	///
	prv := new(big.Int).Mod(
		new(big.Int).Mul(partya.prv, partyb.prv),
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("prv:", prv)
	////
	msg := "hello world"
	hash := crypto.Keccak256Hash([]byte(msg))
	///k_inv * (m + rx * x) mod n
	k_inv := new(big.Int).ModInverse(k, secp256k1.GetSecp256k1().GetN())
	mx := new(big.Int).Mod(
		new(big.Int).Mul(prv, Rx),
		secp256k1.GetSecp256k1().GetN(),
	)
	signs := new(big.Int).Mod(
		new(big.Int).Mul(k_inv, new(big.Int).Add(mx, new(big.Int).SetBytes(hash.Bytes()))),
		secp256k1.GetSecp256k1().GetN(),
	)
	//
	// R: 5cb78d0f81e513b3b2fa9a3882b75166dab95d935a2361a9857387242485ddfc
	// signs: f4948a12cf30daae703ab9b0857aaa9c1a84f353907e33f2c6740b09af90b598
	fmt.Println("signs:", signs.Text(16))
	signature := Rx.Text(16) + signs.Text(16) + "01"
	///
	signPub, err := crypto.Ecrecover(hash.Bytes(), common.Hex2Bytes(signature))
	if err != nil {
		panic(err)
	}
	fmt.Println("signPub:", common.Bytes2Hex(signPub))
}

func Test_paillier_prv(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	Qa, Ra := partya.ZKProof()
	c := partyb.RecvCommit(Qa, Ra)
	s := partya.Challange(c, partyb.Qb, partyb.Rb)
	if partyb.Verify(s) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}
	////
	paillierPrv, paillierPub, err := paillier.GenerateKeyPair(context.Background(), 1024)
	if err != nil {
		panic(err)
	}
	ckey, err := paillierPrv.Encrypt(partya.prv)
	if err != nil {
		panic(err)
	}
	////
	ekey, err := paillierPub.HomoMult(partyb.prv, ckey)
	if err != nil {
		panic(err)
	}
	dkey, err := paillierPrv.Decrypt(ekey)
	if err != nil {
		panic(err)
	}
	key := new(big.Int).Mod(
		dkey,
		secp256k1.GetSecp256k1().GetN(),
	)
	prv := new(big.Int).Mod(
		new(big.Int).Mul(partya.prv, partyb.prv),
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("prv:", prv.Text(16))
	fmt.Println("key:", key.Text(16))
	/////
	// crypto.Sign()
}
func Test_paillier_sign_partial(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	Qa, Ra := partya.ZKProof()
	commit := partyb.RecvCommit(Qa, Ra)
	response := partya.Challange(commit, partyb.Qb, partyb.Rb)
	if partyb.Verify(response) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}
	///
	rx := new(big.Int).Mod(
		partyb.R.GetX().GetNum(),
		secp256k1.GetSecp256k1().GetN(),
	)
	fmt.Println("partyaR:", partya.R.GetX().GetNum())
	fmt.Println("partybR:", partyb.R.GetX().GetNum())
	fmt.Println("      R:", rx)
	////
	paillierPrv, paillierPub, err := paillier.GenerateKeyPair(context.Background(), 1024)
	if err != nil {
		panic(err)
	}
	ckey, err := paillierPub.Encrypt(partya.prv)
	if err != nil {
		panic(err)
	}
	////
	msg := "hello world"
	hash := crypto.Keccak256Hash([]byte(msg))
	////
	k2_inv := new(big.Int).ModInverse(partyb.r, secp256k1.GetSecp256k1().GetN())
	c := new(big.Int).Mod(
		new(big.Int).Mul(k2_inv, new(big.Int).SetBytes(hash.Bytes())),
		secp256k1.GetSecp256k1().GetN(),
	)
	c1, err := paillierPub.Encrypt(c)
	if err != nil {
		panic(err)
	}
	v := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mul(
				k2_inv,
				rx,
			),
			partyb.prv,
		),
		secp256k1.GetSecp256k1().GetN(),
	)
	c2, err := paillierPub.HomoMult(v, ckey)
	if err != nil {
		panic(err)
	}
	c3, err := paillierPub.HomoAdd(c1, c2)
	if err != nil {
		panic(err)
	}
	////
	dc, err := paillierPrv.Decrypt(c3)
	if err != nil {
		panic(err)
	}
	///bed27661c01deb6a106e00b9cc48db3228fdb6d1245aa2fa2d446cbfa5b23abdc39dcb40b673571b037882db0a0c5c06eacf1c92a38a323540b4e3aedad43908
	fmt.Println("dc:", dc.Text(16))
	/////
	k1_inv := new(big.Int).ModInverse(partya.r, secp256k1.GetSecp256k1().GetN())
	s := new(big.Int).Mod(
		new(big.Int).Mul(k1_inv, dc),
		secp256k1.GetSecp256k1().GetN(),
	)
	// R: 5cb78d0f81e513b3b2fa9a3882b75166dab95d935a2361a9857387242485ddfc
	// signs: f4948a12cf30daae703ab9b0857aaa9c1a84f353907e33f2c6740b09af90b598
	fmt.Println("singr:", new(big.Int).Mod(partya.R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN()).Text(16))
	fmt.Println("signs:", s.Text(16))
}
func Test_part(t *testing.T) {
	partya := NewPartyA()
	partyb := NewPartyB()
	/////
	Qa, Ra := partya.ZKProof()
	c := partyb.RecvCommit(Qa, Ra)
	s := partya.Challange(c, partyb.Qb, partyb.Rb)
	if partyb.Verify(s) {
		fmt.Println("verify ok")
	} else {
		panic("verify fail")
	}
	////
	alpha, _ := partyb.PaillierChanllenge(&partya.paillierKey.PublicKey, partya.ckey)
	response := partya.PaillierResponse(alpha)
	if partyb.PaillierVerify(response) {
		fmt.Println("paillier verify ok")
	} else {
		fmt.Println("paillier verify fail")
	}
	////
	msg := "hello world"
	hash := crypto.Keccak256Hash([]byte(msg))
	signaturepartial := partyb.SignaturePartial(hash.Bytes())
	// fmt.Println("signaturepartial:", signaturepartial.String())
	signature := partya.Sign(signaturepartial, hash.Bytes())
	// fmt.Println("signature:", signature)
	////r s v
	// fmt.Println("R:", partya.R.Print())
	fmt.Println("R:", new(big.Int).Mod(partyb.R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN()).Text(16))
	///5cb78d0f81e513b3b2fa9a3882b75166dab95d935a2361a9857387242485ddfc
	// f4948a12cf30daae703ab9b0857aaa9c1a84f353907e33f2c6740b09af90b598
	// 01
	fmt.Println("signr:", common.Bytes2Hex(signature[0:32]))
	fmt.Println("signs:", common.Bytes2Hex(signature[32:64]))

	pubkey := ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     partya.Qpub.GetX().GetNum(),
		Y:     partya.Qpub.GetY().GetNum(),
	}
	fmt.Println("pub:", common.Bytes2Hex(crypto.FromECDSAPub(&pubkey)))
	signPub, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		panic(err)
	}
	fmt.Println("signPub:", common.Bytes2Hex(signPub))
}
