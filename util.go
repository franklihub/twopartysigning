package twoecdsa

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

func RecoverPlain(R, S, Vb *big.Int, homestead bool) []byte {
	if Vb.BitLen() > 8 {
		return nil
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return nil
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	return sig
}
