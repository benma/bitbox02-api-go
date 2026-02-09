// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	result, err := hex.DecodeString(s)
	require.NoError(t, err)
	return result
}

func TestComputePaymentRequestSighashCoinPurchaseMemo(t *testing.T) {
	const (
		outputValue   = uint64(123456)
		outputAddress = "bc1q2q0j6gmfxynj40p0kxsr9jkagcvgpuqvqynnup"
	)

	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "ACME Exchange",
		Nonce:         []byte("nonce-123"),
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_TextMemo_{
					TextMemo: &messages.BTCPaymentRequestRequest_Memo_TextMemo{
						Note: "Invoice #12345",
					},
				},
			},
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: 60,
						Amount:   "0.5 ETH",
						Address:  "0x0123456789abcdef0123456789abcdef01234567",
					},
				},
			},
		},
	}

	sighash, err := ComputePaymentRequestSighash(paymentRequest, 0, outputValue, outputAddress)
	require.NoError(t, err)
	require.Equal(t, mustHexDecode(t, "23b6bfb4aa0f9114802282f6af074f85fe67384425bd3646497c27471bb611eb"), sighash)

	paymentRequest.Memos[1].Memo = &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
		CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
			CoinType: 61,
			Amount:   "0.5 ETH",
			Address:  "0x0123456789abcdef0123456789abcdef01234567",
		},
	}
	sighash, err = ComputePaymentRequestSighash(paymentRequest, 0, outputValue, outputAddress)
	require.NoError(t, err)
	require.NotEqual(t, mustHexDecode(t, "23b6bfb4aa0f9114802282f6af074f85fe67384425bd3646497c27471bb611eb"), sighash)
}

func TestComputePaymentRequestSighashUnsupportedMemoType(t *testing.T) {
	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "Test Merchant",
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{},
		},
	}
	_, err := ComputePaymentRequestSighash(paymentRequest, 0, 1, "bc1q9kvhpyd32aqhpsc8yrdm48gx5dnadq63lservm")
	require.EqualError(t, err, "unsupported memo type")
}

func TestSlip24SampleSignatureWithDemoKey(t *testing.T) {
	const providedSignatureB64 = "yCIolSNPeicNok9/VV4L1dblLmg/SeThMEvptwkiZ514sntSs4/CL+nKorwhsB8P2GiuVYHNV+L82eQVN5Zv2Q=="

	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "SWAPKIT (NEAR)",
		Nonce:         nil,
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: 60,
						Amount:   "0.25 ETH",
						Address:  "0xUserReceiveEthAddress",
					},
				},
			},
		},
	}

	sighash, err := ComputePaymentRequestSighash(
		paymentRequest,
		1, // Testnet (SLIP-44)
		70000000,
		"bc1qProvider_Vault_address000...",
	)
	require.NoError(t, err)
	require.Equal(t, "fd0fbaff2904670c3599af8fe90708ae7d96fa4adef80498b548177fe6f47dd0", hex.EncodeToString(sighash))

	privKey, _ := btcec.PrivKeyFromBytes([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	signatureCompact, err := ecdsa.SignCompact(privKey, sighash, true)
	require.NoError(t, err)
	computedSignature := signatureCompact[1:]
	require.Equal(t, "8hhBVdGiwsbrrECUK/Iu+r/+EO26oOTFBvMYAaEKMbUvtsKLRMaX1BfgR+2ecR0JZMh+xoC4Zgw+XHxlKaWKrA==",
		base64.StdEncoding.EncodeToString(computedSignature))

	providedSignature, err := base64.StdEncoding.DecodeString(providedSignatureB64)
	require.NoError(t, err)
	require.Len(t, providedSignature, 64)
	require.NotEqual(t, providedSignature, computedSignature)
}
