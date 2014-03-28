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
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/cmars/hockeypuck/util"
)

type Loader struct {
	db   *DB
	tx   *sqlx.Tx
	bulk bool
}

func NewLoader(db *DB, bulk bool) *Loader {
	return &Loader{db: db, bulk: bulk}
}

func (l *Loader) Begin() (_ *sqlx.Tx, err error) {
	l.tx, err = l.db.Beginx()
	return l.tx, err
}

func (l *Loader) Commit() (err error) {
	if err = l.tx.Commit(); err != nil {
		return
	}
	return
}

func (l *Loader) Rollback() (err error) {
	err = l.tx.Rollback()
	return
}

func (l *Loader) InsertKey(pubkey *Pubkey) (err error) {
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if err := l.insertPubkey(r); err != nil {
				return err
			}
			signable = r
		case *Subkey:
			if err := l.insertSubkey(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserId:
			if err := l.insertUid(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			if err := l.insertUat(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *Signature:
			if err := l.insertSig(pubkey, signable, r); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (l *Loader) insertPubkey(r *Pubkey) error {
  // The revocation is stored as a :SIGNS with sigType=32.

	_, err := l.tx.Execv(`
      MERGE (key:PubKey { r_keyid:{10} })
      SET key = { uuid:{0}, creation:{1}, expiration:{2}, state:{3}, 
              packet:{4}, ctime:TIMESTAMP(), mtime:TIMESTAMP(), 
              md5:{5}, sha256:{6}, algorithm:{7}, bit_len:{8}, unsupp:{9},
              r_keyid:{10} }
              `,
    r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet, r.Md5,
    r.Sha256, r.Algorithm, r.BitLen, r.Unsupported, r.RKeyId())

  return err
}

func (l *Loader) insertSubkey(pubkey *Pubkey, r *Subkey) error {
    _, err := l.tx.Execv(`
            MERGE (subkey:SubKey { uuid:{0} })
            SET subkey = { uuid:{0}, creation:{1}, expiration:{2}, state:{3}, 
            packet:{4}, algorithm:{5}, bit_len:{6}, r_keyid:{7} }
            WITH subkey
            MATCH (pubkey:PubKey { uuid:{8} })
            MERGE (subkey)-[:BELONGS_TO]->(pubkey)`,
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
    r.Algorithm, r.BitLen, r.RKeyId(), pubkey.RFingerprint)
	return err
}

func (l *Loader) insertUid(pubkey *Pubkey, r *UserId) error {
	_, err := l.tx.Execv(
        `MERGE (uid:UID { uuid:{0} })
        SET uid = { uuid:{0}, creation:{1}, expiration:{2}, state:{3},
                    packet:{4}, keywords:{5}, keywords_fulltext:{5} }
        WITH uid
        MATCH (key:PubKey { uuid:{6} })
        MERGE (uid)-[:IDENTIFIES]->(key)`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		util.CleanUtf8(r.Keywords), pubkey.RFingerprint)
	return err
}

func (l *Loader) insertUat(pubkey *Pubkey, r *UserAttribute) error {
    _, err := l.tx.Execv(`
        MERGE (uat:UAT { uuid:{0} })
        SET uat = { uuid:{0}, creation:{1}, expiration:{2}, state:{3},
                    packet:{4} }
        WITH uat
        MATCH (key:PubKey { uuid:{5} })
        MERGE (uat)-[:IDENTIFIES]->(key)`,
    r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
    pubkey.RFingerprint)
	return err
}

func (l *Loader) insertSig(pubkey *Pubkey, signable PacketRecord, r *Signature) error {
	var cypher string
    var signedType string
    var signedIdentifier string

	switch signed := signable.(type) {
	case *Pubkey:
        signedType = "PubKey"
        signedIdentifier = signed.RFingerprint
	case *Subkey:
        signedType = "SubKey"
        signedIdentifier = signed.RFingerprint
	case *UserId:
        signedType = "UID"
        signedIdentifier = signed.ScopedDigest
	case *UserAttribute:
        signedType = "UAT"
        signedIdentifier = signed.ScopedDigest
	case *Signature:
        signedType = "Signature"
        signedIdentifier = signed.ScopedDigest
	default:
		return fmt.Errorf("Unsupported packet record type: %v", signed)
	}

    cypher = fmt.Sprintf(
        `MATCH (signed:%s { uuid:{0} })
         MERGE (signer:PubKey { r_keyid:{1} })
         MERGE (signer)-[:SIGNS {
             uuid:{2}, creation:{3}, expiration:{4}, state:{5}, packet:{6},
             sig_type:{7}
         }]->(signed)`,
         signedType)

	_, err := l.tx.Execv(cypher, signedIdentifier, r.RIssuerKeyId,
            r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
            r.SigType)
	return err
}
