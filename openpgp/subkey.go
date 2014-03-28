/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package openpgp

import (
	"bytes"
	"database/sql"
	"io"
	"log"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp/packet"

	"github.com/cmars/hockeypuck/types"
	"github.com/cmars/hockeypuck/util"
)

type Subkey struct {
	RFingerprint string         `db:"uuid"`        // immutable
	Creation     types.WrappedTime `db:"creation"`    // immutable
	Expiration   types.WrappedTime `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       types.WrappedByteArray `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable
	Algorithm    int            `db:"algorithm"`   // immutable
	BitLen       int            `db:"bit_len"`     // immutable

	/* Containment references */

	signatures []*Signature `db:"-"`

	/* Cross-references */

	revSig     *Signature `db:"-"`
	bindingSig *Signature `db:"-"`

	/* Parsed packet data */

	PublicKey   *packet.PublicKey
	PublicKeyV3 *packet.PublicKeyV3
}

func (subkey *Subkey) Fingerprint() string {
	return util.Reverse(subkey.RFingerprint)
}

func (subkey *Subkey) KeyId() string {
	return util.Reverse(subkey.RKeyId())
}

func (subkey *Subkey) RKeyId() string {
	return subkey.RFingerprint[:16]
}

func (subkey *Subkey) ShortId() string {
	return util.Reverse(subkey.RFingerprint[:8])
}

func (subkey *Subkey) Signatures() []*Signature { return subkey.signatures }

func (subkey *Subkey) Serialize(w io.Writer) error {
	_, err := w.Write(subkey.Packet.Bytes)
	return err
}

func (subkey *Subkey) Uuid() string { return subkey.RFingerprint }

func (subkey *Subkey) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(subkey.Packet.Bytes)
}

func (subkey *Subkey) GetPacket() (p packet.Packet, err error) {
	if subkey.PublicKey != nil {
		p = subkey.PublicKey
	} else if subkey.PublicKeyV3 != nil {
		p = subkey.PublicKeyV3
	} else {
		err = ErrPacketRecordState
	}
	return
}

func (subkey *Subkey) setPacket(p packet.Packet) (err error) {
	switch pk := p.(type) {
	case *packet.PublicKey:
		if !pk.IsSubkey {
			return ErrInvalidPacketType
		}
		subkey.PublicKey = pk
	case *packet.PublicKeyV3:
		if !pk.IsSubkey {
			return ErrInvalidPacketType
		}
		subkey.PublicKeyV3 = pk
	default:
		err = ErrInvalidPacketType
	}
	return
}

func (subkey *Subkey) Read() (err error) {
	buf := bytes.NewBuffer(subkey.Packet.Bytes)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return err
	}
	return subkey.setPacket(p)
}

func NewSubkey(op *packet.OpaquePacket) (subkey *Subkey, err error) {
	var buf bytes.Buffer
	if err = op.Serialize(&buf); err != nil {
		return
	}
	subkey = &Subkey{Packet: types.WrappedByteArray{Bytes: buf.Bytes()}}
	var p packet.Packet
	if p, err = op.Parse(); err != nil {
		return
	}
	if err = subkey.setPacket(p); err != nil {
		return
	}
	if subkey.PublicKey != nil {
		err = subkey.initV4()
	} else if subkey.PublicKeyV3 != nil {
		err = subkey.initV3()
	} else {
		err = ErrInvalidPacketType
	}
	return
}

func (subkey *Subkey) initV4() error {
	fingerprint := Fingerprint(subkey.PublicKey)
	bitLen, err := subkey.PublicKey.BitLength()
	if err != nil {
		return err
	}
	if !subkey.PublicKey.IsSubkey {
		log.Println("Expected sub-key packet, got primary public key")
		return ErrInvalidPacketType
	}
	subkey.RFingerprint = util.Reverse(fingerprint)
	subkey.Creation.Time = subkey.PublicKey.CreationTime
	subkey.Expiration.Time = NeverExpires
	subkey.Algorithm = int(subkey.PublicKey.PubKeyAlgo)
	subkey.BitLen = int(bitLen)
	return nil
}

func (subkey *Subkey) initV3() error {
	fingerprint := FingerprintV3(subkey.PublicKeyV3)
	bitLen, err := subkey.PublicKeyV3.BitLength()
	if err != nil {
		return err
	}
	if subkey.PublicKeyV3.IsSubkey {
		log.Println("Expected primary public key packet, got sub-key")
		return ErrInvalidPacketType
	}
	subkey.RFingerprint = util.Reverse(fingerprint)
	subkey.Creation.Time = subkey.PublicKeyV3.CreationTime
	subkey.Expiration.Time = NeverExpires
	if subkey.PublicKeyV3.DaysToExpire > 0 {
		subkey.Expiration.Time = subkey.Creation.Add(time.Duration(subkey.PublicKeyV3.DaysToExpire) * time.Hour * 24)
	}
	subkey.Algorithm = int(subkey.PublicKeyV3.PubKeyAlgo)
	subkey.BitLen = int(bitLen)
	return nil
}

func (subkey *Subkey) Visit(visitor PacketVisitor) (err error) {
	err = visitor(subkey)
	if err != nil {
		return
	}
	for _, sig := range subkey.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

func (subkey *Subkey) AddSignature(sig *Signature) {
	subkey.signatures = append(subkey.signatures, sig)
}

func (subkey *Subkey) RemoveSignature(sig *Signature) {
	subkey.signatures = removeSignature(subkey.signatures, sig)
}

func (subkey *Subkey) linkSelfSigs(pubkey *Pubkey) {
	for _, sig := range subkey.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x20 { // TODO: add packet.SigTypeKeyRevocation
			// Use the earliest valid revocation of this key
			if subkey.revSig == nil || sig.Creation.Unix() < subkey.revSig.Creation.Unix() {
				if err := pubkey.verifyPublicKeySelfSig(subkey, sig); err == nil {
					subkey.revSig = sig
					subkey.RevSigDigest = sql.NullString{sig.ScopedDigest, true}
				}
			}
		} else if sig.SigType == 0x18 && time.Now().Unix() < sig.Expiration.Unix() { // TODO: add packet.SigTypeSubkeyBinding
			if err := pubkey.verifyPublicKeySelfSig(subkey, sig); err == nil {
				if sig.Expiration.Unix() == NeverExpires.Unix() && sig.Signature != nil && sig.Signature.KeyLifetimeSecs != nil {
					sig.Expiration.Time = subkey.Creation.Add(
						time.Duration(*sig.Signature.KeyLifetimeSecs) * time.Second)
				}
				if subkey.bindingSig == nil || sig.Creation.Unix() < subkey.bindingSig.Creation.Unix() {
					subkey.bindingSig = sig
					subkey.PubkeyRFP = pubkey.RFingerprint
				}
			}
		}
	}
	// Remove subkeys without a binding signature
	if subkey.bindingSig == nil {
		subkey.State |= PacketStateNoBindingSig
	}
}

func (subkey *Subkey) publicKey() *packet.PublicKey     { return subkey.PublicKey }
func (subkey *Subkey) publicKeyV3() *packet.PublicKeyV3 { return subkey.PublicKeyV3 }
