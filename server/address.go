package server

import (
	"github.com/btcsuite/btcd/chaincfg"
)

type AddressPassThrough string

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a AddressPassThrough) EncodeAddress() string {
	return string(a)
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a pubkey hash.  Part of the Address interface.
func (a AddressPassThrough) ScriptAddress() []byte {
	return []byte{}
}

// IsForNet returns whether or not the pay-to-pubkey-hash address is associated
// with the passed bitcoin network.
func (a AddressPassThrough) IsForNet(net *chaincfg.Params) bool {
	return false
}

// String returns a human-readable string for the pay-to-pubkey-hash address.
// This is equivalent to calling EncodeAddress, but is provided so the type can
// be used as a fmt.Stringer.
func (a AddressPassThrough) String() string {
	return a.EncodeAddress()
}

