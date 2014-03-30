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
	"crypto/rand"
	"encoding/ascii85"
	"fmt"
	"io"
	"log"
	"time"

	"code.google.com/p/go.crypto/openpgp/armor"
	"github.com/juju/errgo/errors"

	. "github.com/cmars/hockeypuck/errors"
	"github.com/cmars/hockeypuck/hkp"
)

// KeyChangeChan channels are used for sending and receiving
// key changes resulting from adding a new key or merging
// updates into an existing one.
type KeyChangeChan chan *KeyChange

// Add responds to /pks/add HKP requests.
func (w *Worker) Add(a *hkp.Add) {
	// Parse armored keytext
	var changes []*KeyChange
	var readErrors []*ReadKeyResult
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(a.Keytext))
	if err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	if _, err = w.Begin(); err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	for readKey := range ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			readErrors = append(readErrors, readKey)
		} else {
			change := w.UpsertKey(readKey.Pubkey)
			if change.Error != nil {
				log.Printf("Error updating key [%s]: %v\n", readKey.Pubkey.Fingerprint(),
					change.Error)
			}
			go w.notifyChange(change)
			changes = append(changes, change)
		}
	}
	if err = w.Commit(); err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
}

// recoverKey responds to public keys recovered from the recon
// protocol.
func (w *Worker) recoverKey(rk *RecoverKey) hkp.Response {
	resp := &RecoverKeyResponse{}
	// Attempt to parse and upsert key
	var pubkeys []*Pubkey
	var err error
	for readKey := range ReadKeys(bytes.NewBuffer(rk.Keytext)) {
		if readKey.Error != nil {
			err = readKey.Error
		} else {
			pubkeys = append(pubkeys, readKey.Pubkey)
		}
	}
	if err != nil {
		return &ErrorResponse{err}
	}
	if len(pubkeys) == 0 {
		return &ErrorResponse{ErrKeyNotFound}
	} else if len(pubkeys) > 1 {
		return &ErrorResponse{ErrTooManyResponses}
	}
	if _, err = w.Begin(); err != nil {
		return &ErrorResponse{err}
	}
	resp.Change = w.UpsertKey(pubkeys[0])
	if err = w.Commit(); err != nil {
		return &ErrorResponse{err}
	}
	w.notifyChange(resp.Change)
	return resp
}

// ErrSubKeyChanges is an error occurring when attempting to subscribe
// to KeyChange messages on a worker that already has a subscriber.
var ErrSubKeyChanges error = errors.New("Worker already has a key change subscriber")

// SubKeyChanges subscribes a KeyChange channel to receive updates on
// any keys added or updated by this worker.
func (w *Worker) SubKeyChanges(keyChanges KeyChangeChan) error {
	if w.keyChanges != nil {
		return ErrSubKeyChanges
	}
	w.keyChanges = keyChanges
	return nil
}

// notifyChange is used by the worker to broadcast key changes
// to a subscriber, if any.
func (w *Worker) notifyChange(keyChange *KeyChange) {
	if w.keyChanges != nil {
		w.keyChanges <- keyChange
	}
}

// KeyChangeType identifies the type of change that a worker has
// made to a public key.
type KeyChangeType int

const (
	// KeyChangeInvalid indicates that the attempted key change information
	// does not describe an expected, valid event.
	KeyChangeInvalid KeyChangeType = iota
	// KeyNotChanged indicates that a request to update an existing public key
	// did not result in any change or addition of new key material.
	KeyNotChanged KeyChangeType = iota
	// KeyAdded indicates a new key was added to the database.
	KeyAdded KeyChangeType = iota
	// KeyModified indicates that an existing key was updated with new information.
	KeyModified KeyChangeType = iota
)

// KeyChange describes the change made to a public key resulting from
// a /pks/add HKP request.
type KeyChange struct {
	// Fingerprint is the public key fingerprint
	Fingerprint string
	// CurrentMd5 contains the new digest of the key (SKS compatible).
	CurrentMd5 string
	// PreviousMd5 contains the digest of the key prior to update, if any (SKS compatible).
	PreviousMd5 string
	// CurrentSha256 contains the new digest of the key.
	CurrentSha256 string
	// PreviousSha256 contains the digest of the key prior to update, if any.
	PreviousSha256 string
	// Error captures the error that prevented the change from occurring, otherwise nil.
	Error error
	// Type indicates the type of key change that occurred, as indicated by KeyChangeType.
	Type KeyChangeType
}

// String represents the key change event as a string for diagnostic purposes.
func (kc *KeyChange) String() string {
	w := bytes.NewBuffer(nil)
	var msg string
	switch kc.Type {
	case KeyChangeInvalid:
		msg = fmt.Sprintf("Invalid key change for [%s] could not be processed",
			kc.Fingerprint)
	case KeyAdded:
		msg = fmt.Sprintf("Add key %s, [%s..]", kc.Fingerprint, kc.CurrentSha256[:8])
	case KeyModified:
		msg = fmt.Sprintf("Modify key %s, [%s.. -> %s..]", kc.Fingerprint,
			kc.PreviousSha256[:8], kc.CurrentSha256[:8])
	case KeyNotChanged:
		msg = fmt.Sprintf("No change in key %s", kc.Fingerprint)
	}
	w.Write([]byte(msg))
	if kc.Error != nil {
		w.Write([]byte(fmt.Sprintf(": Error: %v", kc.Error)))
	}
	return w.String()
}

func (change *KeyChange) calcType() KeyChangeType {
	if change.CurrentSha256 == "" {
		return KeyChangeInvalid
	} else if change.PreviousSha256 == "" {
		return KeyAdded
	} else if change.PreviousSha256 == change.CurrentSha256 {
		return KeyNotChanged
	}
	return KeyModified
}

func (w *Worker) UpsertKey(key *Pubkey) (change *KeyChange) {
	change = &KeyChange{
		Fingerprint:   key.Fingerprint(),
		Type:          KeyChangeInvalid,
		CurrentMd5:    key.Md5,
		CurrentSha256: key.Sha256}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == ErrKeyNotFound {
		change.Type = KeyAdded
	} else if err != nil {
		change.Error = err
		return
	} else {
		change.PreviousMd5 = lastKey.Md5
		change.PreviousSha256 = lastKey.Sha256
		MergeKey(lastKey, key)
		change.CurrentMd5 = lastKey.Md5
		change.CurrentSha256 = lastKey.Sha256
		if change.PreviousMd5 == change.CurrentMd5 && change.PreviousSha256 == change.CurrentSha256 {
			change.Type = KeyNotChanged
		} else {
			change.Type = KeyModified
		}
	}
	if change.CurrentSha256 == "" {
		change.Type = KeyChangeInvalid
	}
	switch change.Type {
	case KeyModified:
		lastKey.Mtime.Time = time.Now()
		if change.Error = w.UpdateKey(lastKey); change.Error == nil {
			w.UpdateKeyRelations(lastKey)
		} else {
			log.Println(change.Error)
		}
	case KeyAdded:
		key.Ctime.Time = time.Now()
		key.Mtime.Time = key.Ctime.Time
		if change.Error = w.InsertKey(key); change.Error == nil {
			w.UpdateKeyRelations(key)
		} else {
			log.Println(change.Error)
		}
	}
	if change.Type != KeyNotChanged {
		log.Println(change)
	}
	return
}

// UpdateKey updates the database to the contents of the given public key.
func (w *Worker) UpdateKey(pubkey *Pubkey) (err error) {
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) (err error) {
		switch r := rec.(type) {
		case *Pubkey:
			_, err := w.db.Execv(`
				MATCH (key:PubKey { uuid:{0} })
				SET key.creation = {1}
				SET key.expiration = {2}
				SET key.state = {3}
				SET key.packet = {4}
				SET key.ctime = {5}
				SET key.mtime = {6}
				SET key.md5 = {7}
				SET key.sha256 = {8}
				SET key.algorithm = {9}
				SET key.bit_len = {10}
				SET key.unsupp = {11}`,
				r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
				r.Ctime, r.Mtime, r.Md5, r.Sha256, r.Algorithm, r.BitLen,
				r.Unsupported)
			if err != nil {
				return errors.Mask(err)
			}
			signable = r
		case *Subkey:
			_, err := w.tx.Execv(`
					MATCH (key:SubKey { uuid:{0} })
					SET key.creation = {1}
					SET key.expiration = {2}
					SET key.state = {3}
					SET key.packet = {4}
					SET key.algorithm = {5}
					SET key.bit_len = {6}`,
				r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
				r.Algorithm, r.BitLen)
				//FIXME: r.PubkeyRFP and r.RevSigDigest
			if err != nil {
				return errors.Mask(err)
			}
			signable = r
		case *UserId:
			_, err := w.tx.Execv(`
					MATCH (uid:UID { uuid:{0} })
					SET uid.creation = {1}
					SET uid.expiration = {2}
					SET uid.state = {3}
					SET uid.packet = {4}
					SET uid.keywords = {5}`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
				r.Keywords)
				// FIXME: RevSigDigest
			if err != nil {
				return errors.Mask(err)
			}
			signable = r
		case *UserAttribute:
			_, err := w.tx.Execv(`
					MATCH (uat:UAT { uuid:{0} })
					SET uat.creation = {1}
					SET uat.expiration = {2}
					SET uat.state = {3}
					SET uat.packet = {4}`,
				r.ScopedDigest,
				r.Creation, r.Expiration, r.State, r.Packet)
				// FIXME: RevSigDigest
			if err != nil {
				return errors.Mask(err)
			}
			signable = r
		case *Signature:
			_, err := w.tx.Execv(`
					MATCH (signer)-[sig:SIGNS { uuid:{0} }]->(signed)
					SET sig.creation = {1}
					SET sig.expiration = {2}
					SET sig.state = {3}
					SET sig.packet = {4}
					SET sig.sig_type = {5}
					SET sig.signer = {6}`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
				r.SigType, r.RIssuerKeyId)
			if err != nil {
				return errors.Mask(err)
			}
		}
		return nil
	})
	return
}

// UUID_LEN is the size of unique primary keys generated for certain
// database records. The length is chosen to approximate 256 bits of security.
// When Ascii85 encoding is used, log(2**256, 85) = 39.9413926456896
const UUID_LEN = 40

// NewUuid creates a new randomly generated, secure unique identifier.
func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := ascii85.NewEncoder(buf)
	n, err := io.CopyN(enc, rand.Reader, UUID_LEN)
	if err != nil {
		return "", err
	}
	if n < UUID_LEN {
		return "", errors.New("Failed to generate UUID")
	}
	return string(buf.Bytes()), nil
}

// UpdateKeyRelations updates the foreign-key relations between
// matching public key packet records to represent the state of the
// given public key.
func (w *Worker) UpdateKeyRelations(pubkey *Pubkey) (err error) {
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			signable = r
		case *Subkey:
			signable = r
		case *UserId:
			return w.updatePrimaryUid(pubkey, r)
			signable = r
		case *UserAttribute:
			return w.updatePrimaryUat(pubkey, r)
			signable = r
		case *Signature:
			switch s := signable.(type) {
			case *Pubkey:
				return w.updatePubkeyRevsig(s, r)
			case *Subkey:
				return w.updateSubkeyRevsig(s, r)
			case *UserId:
				return w.updateUidRevsig(s, r)
			case *UserAttribute:
				return w.updateUatRevsig(s, r)
			}
		}
		return nil
	})
	return
}

func (w *Worker) updatePubkeyRevsig(pubkey *Pubkey, r *Signature) error {
	if pubkey.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_pubkey SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return errors.Mask(err)
		}
	}
	return nil
}

func (w *Worker) updateSubkeyRevsig(subkey *Subkey, r *Signature) error {
	if subkey.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_subkey SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, subkey.RFingerprint); err != nil {
			return errors.Mask(err)
		}
	}
	return nil
}

func (w *Worker) updateUidRevsig(uid *UserId, r *Signature) error {
	if uid.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_uid SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, uid.ScopedDigest); err != nil {
			return errors.Mask(err)
		}
	}
	return nil
}

func (w *Worker) updateUatRevsig(uat *UserAttribute, r *Signature) error {
	if uat.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_uat SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, uat.ScopedDigest); err != nil {
			return errors.Mask(err)
		}
	}
	return nil
}

func (w *Worker) updatePrimaryUid(pubkey *Pubkey, r *UserId) error {
	if pubkey.PrimaryUid.String == r.ScopedDigest {
	  w.updatePrimaryUidFor(pubkey)
	}
	return nil
}

func (w *Worker) updatePrimaryUidFor(pubkey *Pubkey) error {
	if _, err := w.tx.Execv(`
	  MATCH (pubkey:PubKey { uuid:{1} }),
			(uid:UID { uuid:{0} })
	  OPTIONAL MATCH (pubkey)-[rel:PRIMARILY_IDENTIFIED_BY]->(q:UID)
	  DELETE rel
	  CREATE (pubkey)-[:PRIMARILY_IDENTIFIED_BY]->(uid)`,
		pubkey.PrimaryUid.String, pubkey.RFingerprint); err != nil {
		return errors.Mask(err)
	}
	return nil
}

func (w *Worker) updatePrimaryUat(pubkey *Pubkey, r *UserAttribute) error {
	if pubkey.PrimaryUat.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
          MATCH (pubkey:PubKey { uuid:{1} }),
                (uat:UAT { uuid:{0} })
          OPTIONAL MATCH (pubkey)-[rel:PRIMARILY_IDENTIFIED_BY]->(q:UAT)
          DELETE rel
          CREATE (pubkey)-[:PRIMARILY_IDENTIFIED_BY]->(uat)`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return errors.Mask(err)
		}
	}
	return nil
}
