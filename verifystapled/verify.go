package verifystapled

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/hlandau/xlog"

	"github.com/namecoin/ncbtcjson"
	"github.com/namecoin/ncrpcclient"
)

var log, logPublic = xlog.New("encaya.verifystapled")

var Log = logPublic

type StapledData struct {
	// To avoid cross-protocol attacks
	MessageHeader string
	PubType string

	// Domain name
	Domain string

	// Certified keys and certifying sigs (including Namecoin addresses/names)
	PubBase64 string
	SigsJSON string

	// Usage Constraints
	NotAfter string
}

func (sd *StapledData) Verify(namecoin *ncrpcclient.Client) (ok bool, err error) {
	if sd.MessageHeader == "" {
		// This is a software bug.
		return false, fmt.Errorf("empty message header")
	}

	if sd.PubType == "" {
		// This is a software bug.
		return false, fmt.Errorf("empty pubtype")
	}

	if sd.PubBase64 == "" {
		log.Debugf("empty stapled public key: %s", sd.Domain)
		return false, nil
	}

	if sd.SigsJSON == "" {
		log.Debugf("empty stapled signature list: %s", sd.Domain)
		return false, nil
	}

	var blockchainName string

	// Remove eTLD suffix
	if strings.HasSuffix(sd.Domain, ".bit") {
		blockchainName = strings.TrimSuffix(sd.Domain, ".bit")
	} else if strings.HasSuffix(sd.Domain, ".bit.onion") {
		blockchainName = strings.TrimSuffix(sd.Domain, ".bit.onion")
	} else {
		log.Debugf("eTLD doesn't support blockchain messages: %s", sd.Domain)
		return false, nil
	}

	// Remove subdomain labels
	labels := strings.Split(blockchainName, ".")
	blockchainName = labels[len(labels)-1]

	// Prepend blockchain namespace
	blockchainName = "d/" + blockchainName

	sigs := []map[string]string{}

	err = json.Unmarshal([]byte(sd.SigsJSON), &sigs)
	if err != nil {
		log.Debugf("failed to Unmarshal blockchain message sigs for %s: %s", sd.Domain, err)
		return false, nil
	}

	// TODO: stream isolation
	nameData, err := namecoin.NameShow(blockchainName, &ncbtcjson.NameShowOptions{StreamID: ""})
	if err != nil {
		if jerr, ok := err.(*btcjson.RPCError); ok {
			if jerr.Code == btcjson.ErrRPCWallet {
				// ErrRPCWallet from name_show indicates that
				// the name does not exist.
				log.Debugf("name does not exist on blockchain: %s", sd.Domain)
				return false, nil
			}
		}

		// Some error besides NXDOMAIN happened; pass that error
		// through unaltered.
		log.Debugf("blockchain query failed for %s: %s", sd.Domain, err)
		return false, err
	}

	nameAddress := nameData.Address

	for _, sig := range sigs {
		sigAddress, ok := sig["blockchainaddress"]
		if !ok {
			log.Debugf("stapled signature does not contain address: %s", sd.Domain)
			continue
		}

		if sigAddress != nameAddress {
			log.Debugf("stapled signature's address %s is not the current name owner %s: %s", sigAddress, nameAddress, sd.Domain)
			continue
		}

		addressDecoded := AddressPassThrough(nameAddress)

		messageData := map[string]string{
			sd.PubType: sd.PubBase64,
			"domain": sd.Domain,
			"address": sigAddress,
		}

		if sd.NotAfter != "" {
			messageData["notafter"] = sd.NotAfter
		} else {
			log.Debugf("stapled notafter field missing: %s", sd.Domain)
		}

		messageDataBytes, err := json.Marshal(messageData)
		if err != nil {
			return false, fmt.Errorf("failed to Marshal blockchain message data: %w", err)
		}

		messageStr := sd.MessageHeader + string(messageDataBytes)

		sigSig, ok := sig["blockchainsig"]
		if !ok {
			log.Debugf("stapled signature does not contain signature: %s", sd.Domain)
			continue
		}

		verifyResult, err := namecoin.VerifyMessage(addressDecoded, sigSig, messageStr)
		if err != nil {
			log.Debugf("blockchain message signature verification failed for %s: %s", sd.Domain, err)
			continue
		}
		if !verifyResult {
			log.Debugf("blockchain message signature verification returned false: %s", sd.Domain)
			continue
		}

		// Signature check passed.
		return true, nil
	}

	// No sigs matched. Return no cert.
	log.Debugf("off-chain message list exhausted: %s", sd.Domain)
	return false, nil
}
