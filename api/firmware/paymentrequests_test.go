// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"encoding/base64"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateSwapkitNearSignature(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString("lkziB33Vbq2nv3GYrqBoRVJm3yWUW4NQ0CbOibOCEPQYM+2yZWbxo1EKc5xHHbk33j/OEBrrTBF2nzQOveGImg==")
	if err != nil {
		panic(err)
	}

	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "SWAPKIT (NEAR)",
		Nonce:         nil,
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: 0,
						Amount:   "0.0014172 BTC",
						Address:  "bc1qsf4wt3v2gr0vyfngra8vvs4xlqrz8kelttmzp3",
					},
				},
			},
		},
		TotalAmount: 0,
		Signature:   sig,
	}

	// big endian
	//outputValue := unhex("0000000000000000000000000000000000000000000000000de0b6b3a7640000")
	// little endian
	outputValue := unhex("00e1f50500000000000000000000000000000000000000000000000000000000")
	sighash, err := ComputePaymentRequestSighashBytes(
		paymentRequest,
		60,
		outputValue,
		"0xBc228f346b4bD50ED05366A3806591aFf4C6b924",
	)
	require.NoError(t, err)

	pubKey, err := btcec.ParsePubKey(
		unhex("02bf5740a2b794b33d73358d7313e9cb260058f3ac6c886fcc388d9f3f0b48a90d"))
	require.NoError(t, err)
	require.Truef(
		t,
		parseECDSASignature(t, paymentRequest.Signature).Verify(sighash, pubKey),
		"SWAPKIT (NEAR) fixture signature failed verification for sighash %x",
		sighash,
	)
}
