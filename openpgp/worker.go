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
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/juju/errgo/errors"
	_ "github.com/lib/pq"

	. "github.com/cmars/hockeypuck/errors"
	"github.com/cmars/hockeypuck/hkp"
	"github.com/cmars/hockeypuck/util"
)

const LOOKUP_RESULT_LIMIT = 100

type Worker struct {
	*Loader
	Service    *hkp.Service
	Peer       *SksPeer
	keyChanges KeyChangeChan
}

// Number of workers to spawn
func (s *Settings) NumWorkers() int {
	return s.GetIntDefault("hockeypuck.openpgp.nworkers", runtime.NumCPU())
}

func (s *Settings) Driver() string {
	return s.GetStringDefault("hockeypuck.openpgp.db.driver", "postgres")
}

func currentUsername() (username string) {
	if me, err := user.Current(); err != nil {
		username = os.Getenv("USER")
	} else {
		username = me.Name
	}
	return
}

func (s *Settings) DSN() string {
	return s.GetStringDefault("hockeypuck.openpgp.db.dsn",
		fmt.Sprintf("dbname=hkp host=/var/run/postgresql sslmode=disable user=%s",
			currentUsername()))
}

func NewWorker(service *hkp.Service, peer *SksPeer) (w *Worker, err error) {
	w = &Worker{Loader: &Loader{}, Service: service, Peer: peer}
	if w.db, err = NewDB(); err != nil {
		return
	}
	err = w.db.CreateSchema()
	return
}

func (w *Worker) Run() {
	for {
		select {
		case req, ok := <-w.Service.Requests:
			if !ok {
				return
			}
			switch r := req.(type) {
			case *hkp.Lookup:
				w.Lookup(r)
			case *hkp.Add:
				w.Add(r)
			case *hkp.HashQuery:
				w.HashQuery(r)
			default:
				log.Println("Unsupported HKP service request:", req)
			}
		case r, ok := <-w.Peer.RecoverKey:
			if !ok {
				return
			}
			resp := w.recoverKey(&r)
			log.Println(resp)
			r.response <- resp
		}
	}
}

func (w *Worker) Lookup(l *hkp.Lookup) {
	// Dispatch the lookup operation to the correct query
	if l.Op == hkp.Stats {
		w.Stats(l)
		return
	} else if l.Op == hkp.UnknownOperation {
		l.Response() <- &ErrorResponse{hkp.ErrorUnknownOperation("")}
		return
	}
	var keys []*Pubkey
	var limit int = LOOKUP_RESULT_LIMIT
	var err error
	if l.Op == hkp.HashGet {
		keys, err = w.LookupHash(l.Search)
	} else {
		keys, err = w.LookupKeys(l.Search, limit)
	}
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	// Formulate a response
	var resp hkp.Response
	switch l.Op {
	case hkp.Get:
		resp = &KeyringResponse{keys}
	case hkp.HashGet:
		resp = &KeyringResponse{keys}
	case hkp.Index:
		resp = &IndexResponse{Lookup: l, Keys: keys}
	case hkp.Vindex:
		resp = &IndexResponse{Lookup: l, Keys: keys, Verbose: true}
	default:
		resp = &ErrorResponse{ErrUnsupportedOperation}
		return
	}
	l.Response() <- resp
}

func (w *Worker) HashQuery(hq *hkp.HashQuery) {
	var uuids []string
	for _, digest := range hq.Digests {
		uuid, err := w.lookupMd5Uuid(digest)
		if err != nil {
			log.Println("Hashquery lookup failed:", err)
			hq.Response() <- &ErrorResponse{err}
			return
		}
		uuids = append(uuids, uuid)
	}
	keys := w.fetchKeys(uuids)
	hq.Response() <- &HashQueryResponse{keys.GoodKeys()}
}

func (w *Worker) LookupKeys(search string, limit int) (keys []*Pubkey, err error) {
	uuids, err := w.lookupPubkeyUuids(search, limit)
	return w.fetchKeys(uuids).GoodKeys(), err
}

func (w *Worker) LookupHash(digest string) ([]*Pubkey, error) {
	uuid, err := w.lookupMd5Uuid(digest)
	return w.fetchKeys([]string{uuid}).GoodKeys(), err
}

func (w *Worker) lookupPubkeyUuids(search string, limit int) (uuids []string, err error) {
	if strings.HasPrefix(search, "0x") {
		return w.lookupKeyidUuids(search[2:])
	}
	return w.lookupKeywordUuids(search, limit)
}

func (w *Worker) lookupMd5Uuid(hash string) (uuid string, err error) {
	rows, err := w.db.Queryx(`SELECT uuid FROM openpgp_pubkey WHERE md5 = $1`,
		strings.ToLower(hash))
	if err == sql.ErrNoRows {
		return "", ErrKeyNotFound
	} else if err != nil {
		return
	}
	var uuids []string
	uuids, err = flattenUuidRows(rows)
	if err != nil {
		return
	}
	if len(uuids) < 1 {
		return "", ErrKeyNotFound
	}
	uuid = uuids[0]
	if len(uuids) > 1 {
		return uuid, ErrKeyIdCollision
	}
	return
}

func (w *Worker) lookupKeyidUuids(keyId string) (uuids []string, err error) {
	keyId = strings.ToLower(keyId)
	raw, err := hex.DecodeString(keyId)
	if err != nil {
		return nil, ErrInvalidKeyId
	}
	rKeyId := util.Reverse(keyId)
	switch len(raw) {
	case 16:
		return []string{rKeyId}, nil
	case 20:
		return []string{rKeyId}, nil
	default:
		return nil, ErrInvalidKeyId
	}
    rows, err := w.db.Queryx(`
        MATCH (key:PubKey { r_keyid:{0} })
        RETURN key
        UNION ALL
        MATCH (subkey:SubKey { r_keyid:{0})-[:BELONGS_TO]->(key)
        RETURN key
    `, rKeyId)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}
	return flattenUuidRows(rows)
}

func flattenUuidRows(rows *sqlx.Rows) (uuids []string, err error) {
	for rows.Next() {
		var uuid string
		err = rows.Scan(&uuid)
		if err != nil {
			return
		}
		uuids = append(uuids, uuid)
	}
	return
}

func (w *Worker) lookupKeywordUuids(search string, limit int) (uuids []string, err error) {
	search = strings.Join(strings.Split(search, " "), "+")
	regexp := fmt.Sprintf(".*%s.*", search)
	log.Println("keyword:", search)
	log.Println("regexp:", regexp)
	log.Println("limit:", limit)
	rows, err := w.db.Queryx(`
		MATCH (uid:UID)-[:IDENTIFIES]->(key:PubKey)
		WHERE uid.keywords =~ {0}
		RETURN DISTINCT key.uuid AS uuid
		LIMIT {1}`, regexp, limit)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}
	return flattenUuidRows(rows)
}

var ErrInternalKeyInvalid error = errors.New("Internal integrity error matching key")

func (w *Worker) LookupKey(keyid string) (pubkey *Pubkey, err error) {
	uuids, err := w.lookupKeyidUuids(keyid)
	if err != nil {
		return nil, err
	}
	if len(uuids) < 1 {
		return nil, ErrKeyNotFound
	}
	if len(uuids) > 1 {
		return nil, ErrKeyIdCollision
	}
	return w.fetchKey(uuids[0])
}

func (w *Worker) fetchKeys(uuids []string) (results ReadKeyResults) {
	for _, uuid := range uuids {
		key, err := w.fetchKey(uuid)
		results = append(results, &ReadKeyResult{Pubkey: key, Error: err})
		if err != nil {
			log.Println("Fetch key:", err)
		}
	}
	return
}

func (w *Worker) fetchKey(uuid string) (pubkey *Pubkey, err error) {
	pubkey = new(Pubkey)
	err = w.db.Get(pubkey, `
        MATCH (key:PubKey { uuid:{0} })
        OPTIONAL MATCH (key)-[:REVOKED_BY]->(revsig)
        OPTIONAL MATCH (key)-[:PRIMARILY_IDENTIFIED_BY]->(uid:UID)
        OPTIONAL MATCH (key)-[:PRIMARILY_IDENTIFIED_BY]->(uat:UAT)
        RETURN
            key.uuid AS uuid,
            key.creation AS creation,
            key.expiration AS expiration,
            key.state AS state,
            key.packet AS packet,
            key.ctime AS ctime,
            key.mtime AS mtime,
            key.md5 AS md5,
            key.sha256 AS sha256,
            revsig.uuid AS revsig_uuid,
            uid.uuid AS primary_uid,
            uat.uuid AS primary_uat,
            key.algorithm AS algorithm,
            key.bit_len AS bit_len,
            key.unsupp AS unsupp
    `, uuid)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}
	if err = pubkey.Read(); err != nil {
		return
	}
	// Retrieve all signatures made directly on the primary public key
	sigs := []Signature{}
	err = w.db.Select(&sigs, `
        MATCH (signer:PubKey)-[sig:SIGNS]->(signed:PubKey { uuid:{0} })
        RETURN
            sig.uuid AS uuid,
            sig.creation AS creation,
            sig.expiration AS expiration,
            sig.state AS state,
            sig.packet AS packet,
            sig.sig_type AS sig_type,
            signer.r_keyid AS signer,
            signer.uuid AS signer_uuid,
			signed.uuid AS pubkey_uuid`,
		uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.signatures = toSigPtrSlice(sigs)
	for _, sig := range pubkey.signatures {
		if err = sig.Read(); err != nil {
			return
		}
	}
	// Retrieve all uid records
	uids := []UserId{}
	err = w.db.Select(&uids, `
		MATCH (uid:UID)-[:IDENTIFIES]->(key:PubKey { uuid:{0} })
		RETURN
			uid.uuid AS uuid,
			uid.creation AS creation,
			uid.expiration AS expiration,
			uid.state AS state,
			uid.packet AS packet,
			key.uuid AS pubkey_uuid,
			uid.keywords AS keywords`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.userIds = toUidPtrSlice(uids)
	for _, uid := range pubkey.userIds {
		if err = uid.Read(); err != nil {
			return
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
			MATCH (signer:PubKey)-[sig:SIGNS]->(signed:UID { uuid:{0} })
			RETURN
				sig.uuid AS uuid,
				sig.creation AS creation,
				sig.expiration AS expiration,
				sig.state AS state,
				sig.packet AS packet,
				sig.sig_type AS sig_type,
				signer.r_keyid AS signer,
				signer.uuid AS signer_uuid,
				signed.uuid AS uid_uuid`, uid.ScopedDigest)
		if err != nil && err != sql.ErrNoRows {
			return
		}
		uid.signatures = toSigPtrSlice(sigs)
		for _, sig := range uid.signatures {
			if err = sig.Read(); err != nil {
				return
			}
		}
	}
	// Retrieve all user attribute records
	uats := []UserAttribute{}
	err = w.db.Select(&uats, `
		MATCH (uat:UAT)-[:IDENTIFIES]->(key:PubKey { uuid:{0} })
		RETURN
			uat.uuid AS uuid,
			uat.creation AS creation,
			uat.expiration AS expiration,
			uat.state AS state,
			uat.packet AS packet,
			key.uuid AS pubkey_uuid`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.userAttributes = toUatPtrSlice(uats)
	for _, uat := range pubkey.userAttributes {
		if err = uat.Read(); err != nil {
			return
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
			MATCH (signer:PubKey)-[sig:SIGNS]->(signed:UAT { uuid:{0} })
			RETURN
				sig.uuid AS uuid,
				sig.creation AS creation,
				sig.expiration AS expiration,
				sig.state AS state,
				sig.packet AS packet,
				sig.sig_type AS sig_type,
				signer.r_keyid AS signer,
				signer.uuid AS signer_uuid,
				signed.uuid AS uat_uuid`, uat.ScopedDigest)
		if err != nil && err != sql.ErrNoRows {
			return
		}
		uat.signatures = toSigPtrSlice(sigs)
		for _, sig := range uat.signatures {
			if err = sig.Read(); err != nil {
				return
			}
		}
	}
	// Retrieve all subkey records
	subkeys := []Subkey{}
	err = w.db.Select(&subkeys, `
		MATCH (subkey:SubKey)-[:BELONGS_TO]->(key:PubKey { uuid:{0} })
		RETURN
			subkey.uuid AS uuid,
			subkey.creation AS creation,
			subkey.expiration AS expiration,
			subkey.state AS state,
			subkey.packet AS packet,
			key.uuid AS pubkey_uuid,
			subkey.algorithm AS algorithm,
			subkey.bit_len AS bit_len`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.subkeys = toSubkeyPtrSlice(subkeys)
	for _, subkey := range pubkey.subkeys {
		if err = subkey.Read(); err != nil {
			return
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
			MATCH (signer:PubKey)-[sig:SIGNS]->(signed:SubKey { uuid:{0} })
			RETURN
				sig.uuid AS uuid,
				sig.creation AS creation,
				sig.expiration AS expiration,
				sig.state AS state,
				sig.packet AS packet,
				sig.sig_type AS sig_type,
				signer.r_keyid AS signer,
				signer.uuid AS signer_uuid,
				signed.uuid AS subkey_uuid`, subkey.RFingerprint)
		if err != nil && err != sql.ErrNoRows {
			return
		}
		subkey.signatures = toSigPtrSlice(sigs)
		for _, sig := range subkey.signatures {
			if err = sig.Read(); err != nil {
				return
			}
		}
	}
	Resolve(pubkey)
	return
}

func toSigPtrSlice(recs []Signature) (result []*Signature) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}

func toUidPtrSlice(recs []UserId) (result []*UserId) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}

func toUatPtrSlice(recs []UserAttribute) (result []*UserAttribute) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}

func toSubkeyPtrSlice(recs []Subkey) (result []*Subkey) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}
