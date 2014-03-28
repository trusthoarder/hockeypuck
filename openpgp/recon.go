/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	. "github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"github.com/cmars/conflux/recon/leveldb"

	"github.com/cmars/hockeypuck/hkp"
)

const RequestChunkSize = 100

type SksPeer struct {
	*recon.Peer
	Service    *hkp.Service
	RecoverKey chan RecoverKey
	KeyChanges KeyChangeChan
}

type RecoverKey struct {
	Keytext  []byte
	Source   string
	response hkp.ResponseChan
}

func NewSksPTree(reconSettings *recon.Settings) (recon.PrefixTree, error) {
	treeSettings := leveldb.NewSettings(reconSettings)
	return leveldb.New(treeSettings)
}

func NewSksPeer(s *hkp.Service) (*SksPeer, error) {
	reconSettings := recon.NewSettings(Config().Settings.TomlTree)
	ptree, err := NewSksPTree(reconSettings)
	if err != nil {
		return nil, err
	}
	peer := recon.NewPeer(reconSettings, ptree)
	sksPeer := &SksPeer{
		Peer:       peer,
		Service:    s,
		KeyChanges: make(KeyChangeChan, Config().NumWorkers()*4),
		RecoverKey: make(chan RecoverKey, Config().NumWorkers()*4),
	}
	return sksPeer, nil
}

func (r *SksPeer) Start() {
	r.Peer.PrefixTree.Create()

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case _ = <-sigChan:
      // This should be r.Peer.Stop(), but that deadlocks on serverStop
      // and gossipStop. The implementation in question is on GitHub:
      // http://bit.ly/1mngFdy
      r.Peer.Disable()
      os.Exit(0)
		}
	}()

	go r.HandleRecovery()
	go r.HandleKeyUpdates()
	go r.Peer.Start()
}

func (r *SksPeer) HandleKeyUpdates() {
	for {
		select {
		case keyChange, ok := <-r.KeyChanges:
			if !ok {
				return
			}
			digest, err := hex.DecodeString(keyChange.CurrentMd5)
			if err != nil {
				log.Println("bad digest:", keyChange.CurrentMd5)
				continue
			}
			digest = recon.PadSksElement(digest)
			digestZp := Zb(P_SKS, digest)
			log.Println("Prefix tree: Insert:", hex.EncodeToString(digestZp.Bytes()), keyChange, keyChange.CurrentMd5)
			err = r.Peer.Insert(digestZp)
			if err != nil {
				log.Println(err)
				continue
			}
			if keyChange.PreviousMd5 != "" && keyChange.PreviousMd5 != keyChange.CurrentMd5 {
				prevDigest, err := hex.DecodeString(keyChange.PreviousMd5)
				if err != nil {
					log.Println("bad digest:", keyChange.PreviousMd5)
					continue
				}
				prevDigest = recon.PadSksElement(prevDigest)
				prevDigestZp := Zb(P_SKS, prevDigest)
				log.Println("Prefix Tree: Remove:", prevDigestZp)
				err = r.Peer.Remove(prevDigestZp)
				if err != nil {
					log.Println(err)
					continue
				}
			}
		}
	}
}

func (r *SksPeer) HandleRecovery() {
	rcvrChans := make(map[string]chan *recon.Recover)
	defer func() {
		for _, ch := range rcvrChans {
			close(ch)
		}
	}()
	for {
		select {
		case rcvr, ok := <-r.Peer.RecoverChan:
			if !ok {
				return
			}
			// Use remote HKP host:port as peer-unique identifier
			remoteAddr, err := rcvr.HkpAddr()
			if err != nil {
				continue
			}
			// Mux recoveries to per-address channels
			rcvrChan, has := rcvrChans[remoteAddr]
			if !has {
				rcvrChan = make(chan *recon.Recover)
				rcvrChans[remoteAddr] = rcvrChan
				go r.handleRemoteRecovery(rcvr, rcvrChan)
			}
			rcvrChan <- rcvr
		}
	}
}

type workRecoveredReady chan interface{}
type workRecoveredWork chan *ZSet

func (r *SksPeer) handleRemoteRecovery(rcvr *recon.Recover, rcvrChan chan *recon.Recover) {
	recovered := NewZSet()
	ready := make(workRecoveredReady)
	work := make(workRecoveredWork)
	defer close(work)
	go r.workRecovered(rcvr, ready, work)
	for {
		select {
		case rcvr, ok := <-rcvrChan:
			if !ok {
				return
			}
			// Aggregate recovered IDs
			recovered.AddSlice(rcvr.RemoteElements)
			log.Println("Recovery from", rcvr.RemoteAddr.String(), ":", recovered.Len(), "pending")
			r.Peer.Disable()
		case _, ok := <-ready:
			// Recovery worker is ready for more
			if !ok {
				return
			}
			work <- recovered
			recovered = NewZSet()
		}
	}
}

func (r *SksPeer) workRecovered(rcvr *recon.Recover, ready workRecoveredReady, work workRecoveredWork) {
	defer close(ready)
	timer := time.NewTimer(time.Duration(3) * time.Second)
	defer timer.Stop()
	for {
		select {
		case recovered, ok := <-work:
			if !ok {
				return
			}
			err := r.requestRecovered(rcvr, recovered)
			if err != nil {
				log.Println(err)
			}
			timer.Reset(time.Duration(r.Peer.GossipIntervalSecs()) * time.Second)
			r.Peer.Enable()
		case <-timer.C:
			timer.Stop()
			ready <- new(interface{})
		}
	}
}

func (r *SksPeer) requestRecovered(rcvr *recon.Recover, elements *ZSet) (err error) {
	items := elements.Items()
	for len(items) > 0 {
		// Chunk requests to keep the hashquery message size and peer load reasonable.
		chunksize := RequestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]
		items = items[chunksize:]
		err = r.requestChunk(rcvr, chunk)
		if err != nil {
			log.Println(err)
		}
	}
	return
}

func (r *SksPeer) requestChunk(rcvr *recon.Recover, chunk []*Zp) (err error) {
	var remoteAddr string
	remoteAddr, err = rcvr.HkpAddr()
	if err != nil {
		return err
	}
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(chunk))
	if err != nil {
		return err
	}
	for _, z := range chunk {
		zb := z.Bytes()
		zb = recon.PadSksElement(zb)
		// Hashquery elements are 16 bytes (length_of(P_SKS)-1)
		zb = zb[:len(zb)-1]
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return err
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return err
		}
	}
	resp, err := http.Post(fmt.Sprintf("http://%s/pks/hashquery", remoteAddr),
		"sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
	if err != nil {
		return err
	}
	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	{
		defer resp.Body.Close()
		bodyBuf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(bodyBuf)
	}
	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(body)
	if err != nil {
		return err
	}
	log.Println("Response from server:", nkeys, " keys found")
	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(body)
		if err != nil {
			return err
		}
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, body, int64(keyLen))
		if err != nil {
			return err
		}
		log.Println("Key#", i+1, ":", keyLen, "bytes")
		// Merge locally
		recoverKey := RecoverKey{
			Keytext:  keyBuf.Bytes(),
			Source:   rcvr.RemoteAddr.String(),
			response: make(chan hkp.Response)}
		go func() {
			r.RecoverKey <- recoverKey
		}()
		resp := <-recoverKey.response
		if resp != nil && resp.Error() != nil {
			log.Println("Error adding key:", resp.Error())
		}
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return
}

func (r *SksPeer) Stop() {
	r.Peer.Stop()
}
