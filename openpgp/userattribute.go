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
	"crypto/sha256"
	"database/sql"
	"io"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp/packet"

	"github.com/cmars/hockeypuck/types"
)

type UserAttribute struct {
	ScopedDigest string         `db:"uuid"`        // immutable
	Creation     types.WrappedTime `db:"creation"`    // mutable (derived from latest sigs)
	Expiration   types.WrappedTime `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       types.WrappedByteArray `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable

	/* Cross-references */

	revSig        *Signature   `db:"-"`
	selfSignature *Signature   `db:"-"`
	signatures    []*Signature `db:"-"`

	/* Parsed packet data */

	UserAttribute *packet.UserAttribute
}

func (uat *UserAttribute) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write([]byte("{uat}"))
	h.Write(uat.Packet.Bytes)
	return toAscii85String(h.Sum(nil))
}

func (uat *UserAttribute) Serialize(w io.Writer) error {
	_, err := w.Write(uat.Packet.Bytes)
	return err
}

func (uat *UserAttribute) Uuid() string { return uat.ScopedDigest }

func (uat *UserAttribute) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(uat.Packet.Bytes)
}

func (uat *UserAttribute) GetPacket() (packet.Packet, error) {
	if uat.UserAttribute != nil {
		return uat.UserAttribute, nil
	}
	return nil, ErrPacketRecordState
}

func (uat *UserAttribute) setPacket(p packet.Packet) error {
	u, is := p.(*packet.UserAttribute)
	if !is {
		return ErrInvalidPacketType
	}
	uat.UserAttribute = u
	return nil
}

func (uat *UserAttribute) Read() (err error) {
	buf := bytes.NewBuffer(uat.Packet.Bytes)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return err
	}
	return uat.setPacket(p)
}

func NewUserAttribute(op *packet.OpaquePacket) (uat *UserAttribute, err error) {
	var buf bytes.Buffer
	if err = op.Serialize(&buf); err != nil {
		return
	}
	uat = &UserAttribute{Packet: types.WrappedByteArray{Bytes: buf.Bytes()}}
	var p packet.Packet
	if p, err = op.Parse(); err != nil {
		return
	}
	if err = uat.setPacket(p); err != nil {
		return
	}
	return uat, uat.init()
}

func (uat *UserAttribute) init() (err error) {
	uat.Creation.Time = NeverExpires
	uat.Expiration.Time = time.Unix(0, 0)
	return
}

func (uat *UserAttribute) Visit(visitor PacketVisitor) (err error) {
	err = visitor(uat)
	if err != nil {
		return
	}
	for _, sig := range uat.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

func (uat *UserAttribute) AddSignature(sig *Signature) {
	uat.signatures = append(uat.signatures, sig)
}

func (uat *UserAttribute) RemoveSignature(sig *Signature) {
	uat.signatures = removeSignature(uat.signatures, sig)
}

func (uat *UserAttribute) linkSelfSigs(pubkey *Pubkey) {
	for _, sig := range uat.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x30 { // TODO: add packet.SigTypeCertRevocation
			if uat.revSig == nil || sig.Creation.Unix() > uat.revSig.Creation.Unix() {
				if err := pubkey.verifyUserAttrSelfSig(uat, sig); err == nil {
					uat.revSig = sig
					uat.RevSigDigest = sql.NullString{sig.ScopedDigest, true}
				}
			}
		}
	}
	for _, sig := range uat.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if time.Now().Unix() > sig.Expiration.Unix() {
			// Ignore expired signatures
			continue
		}
		if sig.SigType >= 0x10 && sig.SigType <= 0x13 {
			if err := pubkey.verifyUserAttrSelfSig(uat, sig); err == nil {
				if sig.Expiration.Unix() == NeverExpires.Unix() && sig.Signature != nil && sig.Signature.KeyLifetimeSecs != nil {
					sig.Expiration.Time = pubkey.Creation.Time.Add(
						time.Duration(*sig.Signature.KeyLifetimeSecs) * time.Second)
				}
				if uat.selfSignature == nil || sig.Creation.Unix() > uat.selfSignature.Creation.Unix() {
					uat.selfSignature = sig
				}
				if uat.revSig != nil && sig.Creation.Unix() > uat.selfSignature.Creation.Unix() {
					// A self-certification more recent than a revocation effectively cancels it.
					uat.revSig = nil
					uat.RevSigDigest = sql.NullString{"", false}
				}
			}
		}
	}
	// Flag User Attributes without a self-signature
	if uat.selfSignature == nil {
		uat.State |= PacketStateNoSelfSig
	}
}
