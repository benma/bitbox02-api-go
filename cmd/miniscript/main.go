// Copyright 2023 Shift Crypto AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main is a playground to play with the BitBox02 miniscript support.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/benma/miniscript-go"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/messages"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/mocks"
	"github.com/digitalbitbox/bitbox02-api-go/communication/u2fhid"
	"github.com/karalabe/usb"
)

const (
	bitbox02VendorID  = 0x03eb
	bitbox02ProductID = 0x2403
	bitboxCMD         = 0x80 + 0x40 + 0x01

	HARDENED = 0x80000000
)

func errpanic(err error) {
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

func isBitBox02(deviceInfo usb.DeviceInfo) bool {
	return (deviceInfo.Product == common.FirmwareHIDProductStringStandard ||
		deviceInfo.Product == common.FirmwareHIDProductStringBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

func mustXPub(xpubStr string) *messages.XPub {
	xpub, err := firmware.NewXPub(xpubStr)
	errpanic(err)
	return xpub
}

func parseDescriptor(descriptor string) (*miniscript.AST, error) {
	if strings.HasPrefix(descriptor, "wsh(") && strings.HasSuffix(descriptor, ")") {
		return miniscript.Parse(descriptor[4 : len(descriptor)-1])
	} else {
		return nil, errors.New("Must be a wsh() descriptor")
	}
}

func getKeypathAccount(num uint32) []uint32 {
	return []uint32{48 + HARDENED, 0 + HARDENED, num + HARDENED, 3 + HARDENED}
}

func getBitBox02Keys(device *firmware.Device, coin messages.BTCCoin, ourRootFingerprint []byte, num int) ([]*messages.BTCScriptConfig_Descriptor_Key, []string) {
	keys := make([]*messages.BTCScriptConfig_Descriptor_Key, num)
	xpubs := make([]string, num)
	for i := 0; i < num; i++ {
		keypathAccount := getKeypathAccount(uint32(i))
		ourXPub, err := device.BTCXPub(coin, keypathAccount, messages.BTCPubRequest_XPUB, false)
		xpubs[i] = ourXPub
		errpanic(err)
		keys[i] = &messages.BTCScriptConfig_Descriptor_Key{
			Key: &messages.BTCScriptConfig_Descriptor_Key_KeyOriginInfo{
				KeyOriginInfo: &messages.KeyOriginInfo{
					RootFingerprint: ourRootFingerprint,
					Keypath:         keypathAccount,
					Xpub:            mustXPub(ourXPub),
				},
			},
		}
	}
	return keys, xpubs
}

type multipath struct {
	receiveIndex uint32
	changeIndex  uint32
}

func (m multipath) derivationSuffix(isChange bool, addressIndex uint32) []uint32 {
	if isChange {
		return []uint32{m.changeIndex, addressIndex}
	}
	return []uint32{m.receiveIndex, addressIndex}
}

func main() {
	deviceInfo := func() usb.DeviceInfo {
		infos, err := usb.EnumerateHid(0, 0)
		errpanic(err)
		for _, di := range infos {
			if di.Serial == "" || di.Product == "" {
				continue
			}
			if isBitBox02(di) {
				return di
			}
		}
		panic("could no find a bitbox02")

	}()

	descriptor := "wsh(and_v(v:pk(@0/**),pk(@1/<10;11>/*)))"
	numKeys := 2
	miniscriptNode, err := parseDescriptor(descriptor)
	errpanic(err)

	hidDevice, err := deviceInfo.Open()
	errpanic(err)

	comm := u2fhid.NewCommunication(hidDevice, bitboxCMD)
	device := firmware.NewDevice(nil, nil, &mocks.Config{}, comm, &mocks.Logger{})
	device.Init()
	device.ChannelHashVerify(true)

	ourRootFingerprint, err := device.RootFingerprint()
	errpanic(err)
	fmt.Printf("Root fingerprint: %x\n", ourRootFingerprint)

	coin := messages.BTCCoin_TBTC

	keys, xpubs := getBitBox02Keys(device, coin, ourRootFingerprint, numKeys)

	isChange := false
	deriveAddressIndex := uint32(0)
	//derivationSuffix := []uint32{0, 0}

	pubKeys := make([][]byte, len(xpubs))
	multipaths := make([]multipath, len(xpubs))

	err = miniscriptNode.ApplyVars(func(identifier string) ([]byte, error) {
		matches := regexp.MustCompile(`@(\d+)/(?:\*\*|\<(\d+);(\d+)\>/\*)`).FindStringSubmatch(identifier)
		if len(matches) != 4 {
			return nil, fmt.Errorf("Could not parse: %s", identifier)
		}
		index, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, err
		}
		mp := multipath{0, 1} // default is /<0;1>/
		if len(matches[2]) > 0 && len(matches[3]) > 0 {
			receiveIndex, err := strconv.Atoi(matches[2])
			if err != nil {
				return nil, err
			}
			mp.receiveIndex = uint32(receiveIndex)
			changeIndex, err := strconv.Atoi(matches[3])
			if err != nil {
				return nil, err
			}
			mp.changeIndex = uint32(changeIndex)
		}
		multipaths[index] = mp
		xpubStr := xpubs[index]
		xpub, err := hdkeychain.NewKeyFromString(xpubStr)
		if err != nil {
			return nil, err
		}

		for _, el := range mp.derivationSuffix(isChange, deriveAddressIndex) {
			var err error
			xpub, err = xpub.Derive(el)
			if err != nil {
				return nil, err
			}
		}
		pubkey, err := xpub.ECPubKey()
		if err != nil {
			return nil, err
		}
		pubKeys[index] = pubkey.SerializeCompressed()

		return pubKeys[index], nil
	})
	errpanic(err)

	witnessScript, err := miniscriptNode.Script()
	errpanic(err)
	hostAddress, err := btcutil.NewAddressWitnessScriptHash(chainhash.HashB(witnessScript), &chaincfg.TestNet3Params)
	errpanic(err)

	scriptConfig := &messages.BTCScriptConfig{
		Config: &messages.BTCScriptConfig_Descriptor_{
			Descriptor_: &messages.BTCScriptConfig_Descriptor{
				Descriptor_: descriptor,
				Keys:        keys,
			},
		},
	}

	isRegistered, err := device.BTCIsScriptConfigRegistered(coin, scriptConfig, nil)
	errpanic(err)

	if !isRegistered {
		fmt.Println("Descriptor not registered, registering...")
		err := device.BTCRegisterScriptConfig(coin, scriptConfig, nil, "")
		errpanic(err)
	} else {
		fmt.Println("Descriptor is already registered.")
	}

	{
		// show address
		keypathAccount := getKeypathAccount(0)
		mp := multipaths[0]
		address := func(display bool) string {
			addr, err := device.BTCAddress(coin, append(keypathAccount, mp.derivationSuffix(isChange, deriveAddressIndex)...), scriptConfig, display)
			errpanic(err)
			return addr
		}
		deviceAddress := address(false)
		if deviceAddress != hostAddress.String() {
			log.Printf(
				"Address derived independently on host (%s) does not match address dervied by BitBox02 (%s)",
				hostAddress, deviceAddress)
			return
		}
		fmt.Println("Displaying first address:", deviceAddress)
		address(true)
	}

	// testredeem

	utxoAmount := int64(999799)
	utxoPkScript, err := txscript.PayToAddrScript(hostAddress)
	errpanic(err)

	// Our test spend is a 1-input 1-output transaction. The input is spends the miniscript
	// UTXO. The output is an arbitrary output.
	withdrawToAddress, err := btcutil.DecodeAddress("bc1q77mts6tjfandrmd0wlfceku702n0yfu67ff3ud", &chaincfg.TestNet3Params)
	errpanic(err)
	withdrawToPkScript, err := txscript.PayToAddrScript(withdrawToAddress)
	errpanic(err)
	// Dummy prevout hash.
	prevoutHash, err := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000000")
	errpanic(err)
	txInput := wire.NewTxIn(&wire.OutPoint{Hash: *prevoutHash}, nil, nil)
	txInput.Sequence = 0

	depositTransaction := wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{txInput},
		TxOut:    []*wire.TxOut{{Value: utxoAmount, PkScript: utxoPkScript}},
		LockTime: 0,
	}
	withdrawalTransaction := wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			wire.NewTxIn(&wire.OutPoint{Hash: depositTransaction.TxHash()}, nil, nil),
		},
		TxOut:    []*wire.TxOut{{Value: utxoAmount - 200, PkScript: withdrawToPkScript}},
		LockTime: 0,
	}

	// We only have one input, for which we will execute the script.
	inputIndex := 0
	// We only have one input, so the previous outputs fetcher for the transaction simply returns
	// our UTXO. The previous output is needed as it is signed as part of the the transaction
	// sighash for the input.
	previousOutputs := txscript.NewCannedPrevOutputFetcher(utxoPkScript, utxoAmount)
	// Compute the signature hash to be signed for the first input:
	sigHashes := txscript.NewTxSigHashes(&withdrawalTransaction, previousOutputs)
	// signatureHash as computed/signed by the BitBox02
	// signatureHash, err := txscript.CalcWitnessSigHash(
	// 	witnessScript, sigHashes, txscript.SigHashAll, &withdrawalTransaction, inputIndex, utxoAmount)
	// errpanic(err)

	allSignatures := make([][][]byte, len(keys))
	for i := range keys {
		accountKeypath := getKeypathAccount(uint32(i))
		mp := multipaths[i]
		signatures, err := device.BTCSign(
			coin,
			[]*messages.BTCScriptConfigWithKeypath{
				{
					ScriptConfig: scriptConfig,
					Keypath:      accountKeypath,
				},
			},
			&firmware.BTCTx{
				Version: uint32(withdrawalTransaction.Version),
				Inputs: []*firmware.BTCTxInput{{
					Input: &messages.BTCSignInputRequest{
						PrevOutHash:  withdrawalTransaction.TxIn[0].PreviousOutPoint.Hash[:],
						PrevOutIndex: withdrawalTransaction.TxIn[0].PreviousOutPoint.Index,
						PrevOutValue: uint64(depositTransaction.TxOut[0].Value),
						Sequence:     withdrawalTransaction.TxIn[0].Sequence,
						Keypath:      append(accountKeypath, mp.derivationSuffix(isChange, deriveAddressIndex)...),
					},
					PrevTx: &firmware.BTCPrevTx{
						Version: uint32(depositTransaction.Version),
						Inputs: []*messages.BTCPrevTxInputRequest{
							{
								PrevOutHash:     depositTransaction.TxIn[0].PreviousOutPoint.Hash[:],
								PrevOutIndex:    depositTransaction.TxIn[0].PreviousOutPoint.Index,
								SignatureScript: depositTransaction.TxIn[0].SignatureScript,
								Sequence:        depositTransaction.TxIn[0].Sequence,
							},
						},
						Outputs: []*messages.BTCPrevTxOutputRequest{
							{
								Value:        uint64(depositTransaction.TxOut[0].Value),
								PubkeyScript: depositTransaction.TxOut[0].PkScript,
							},
						},
						Locktime: depositTransaction.LockTime,
					},
				}},
				Outputs: []*messages.BTCSignOutputRequest{
					{
						Ours:    false,
						Type:    messages.BTCOutputType_P2WPKH,
						Value:   uint64(withdrawalTransaction.TxOut[0].Value),
						Payload: withdrawalTransaction.TxOut[0].PkScript[2:],
					},
				},
				Locktime: withdrawalTransaction.LockTime,
			},
			messages.BTCSignInitRequest_DEFAULT,
		)
		errpanic(err)

		// Convert to DER encoding
		signaturesDER := make([][]byte, len(signatures))
		for sigIndex, signature := range signatures {
			r := new(btcec.ModNScalar)
			r.SetByteSlice(signature[:32])
			s := new(btcec.ModNScalar)
			s.SetByteSlice(signature[32:])
			signaturesDER[sigIndex] = ecdsa.NewSignature(r, s).Serialize()
		}
		allSignatures[i] = signaturesDER
	}

	// Construct a satisfaction (witness) from the miniscript.
	witness, err := miniscriptNode.Satisfy(&miniscript.Satisfier{
		CheckOlder: func(locktime uint32) (bool, error) {
			return miniscript.CheckOlder(
				locktime,
				uint32(withdrawalTransaction.Version),
				withdrawalTransaction.TxIn[inputIndex].Sequence,
			), nil
		},
		CheckAfter: func(locktime uint32) (bool, error) {
			return miniscript.CheckAfter(
				locktime,
				withdrawalTransaction.LockTime,
				withdrawalTransaction.TxIn[inputIndex].Sequence,
			), nil
		},
		Sign: func(pubKey []byte) ([]byte, bool) {
			for i, pk := range pubKeys {
				if bytes.Equal(pk, pubKey) {
					signature := allSignatures[i][inputIndex]
					signature = append(signature, byte(txscript.SigHashAll))
					return signature, true
				}
			}
			return nil, false
		},
		Preimage: func(hashFunc string, hash []byte) ([]byte, bool) {
			return nil, false
		},
	})
	errpanic(err)

	// Put the created witness into the transaction input, then execute the script to test that the
	// UTXO can be spent successfully.

	withdrawalTransaction.TxIn[inputIndex].Witness = wire.TxWitness(append(
		witness, witnessScript,
	))
	engine, err := txscript.NewEngine(
		utxoPkScript, &withdrawalTransaction, inputIndex,
		txscript.StandardVerifyFlags, nil, sigHashes, utxoAmount, previousOutputs)
	errpanic(err)
	err = engine.Execute()
	errpanic(err)
	fmt.Println("Transaction successfully signed")
}
