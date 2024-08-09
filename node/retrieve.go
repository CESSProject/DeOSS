package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/erasure"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
)

var (
	retrieve_lock  *sync.Mutex
	retrieve_files map[string]struct{}
)

func init() {
	retrieve_lock = new(sync.Mutex)
	retrieve_files = make(map[string]struct{}, 10)
}

func (n *Node) retrieve_file(fid, savedir, cipher string) (string, error) {
	userfile := filepath.Join(savedir, fid)
	ok := false
	retrieve_lock.Lock()
	if _, ok = retrieve_files[fid]; !ok {
		retrieve_files[fid] = struct{}{}
	}
	retrieve_lock.Unlock()
	if ok {
		tick := time.NewTicker(time.Second * 3)
		for {
			select {
			case <-tick.C:
				retrieve_lock.Lock()
				_, ok = retrieve_files[fid]
				retrieve_lock.Unlock()
				if !ok {
					_, err := os.Stat(userfile)
					return userfile, err
				}
			}
		}
	}

	defer func() {
		retrieve_lock.Lock()
		delete(retrieve_files, fid)
		retrieve_lock.Unlock()
	}()

	fstat, err := os.Stat(userfile)
	if err == nil {
		if fstat.Size() > 0 {
			return userfile, nil
		}
	}
	os.MkdirAll(savedir, 0755)
	f, err := os.Create(userfile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		return "", err
	}

	defer func(basedir string) {
		for _, segment := range fmeta.SegmentList {
			os.Remove(filepath.Join(basedir, string(segment.Hash[:])))
			for _, fragment := range segment.FragmentList {
				os.Remove(filepath.Join(basedir, string(fragment.Hash[:])))
			}
		}
	}(savedir)

	var segmentspath = make([]string, 0)
	fragmentpaths := make([]string, sconfig.DataShards+sconfig.ParShards)

	for _, segment := range fmeta.SegmentList {
		for k, fragment := range segment.FragmentList {
			fragmentpath := filepath.Join(savedir, string(fragment.Hash[:]))
			fragmentpaths[k] = fragmentpath
			n.Logdown("info", "will download fragment: "+string(fragment.Hash[:]))
			if string(fragment.Hash[:]) != "2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74" {
				account, _ := sutils.EncodePublicKeyAsCessAccount(fragment.Miner[:])
				n.Logdown("info", "will query the storage miner: "+account)
				miner, err := n.QueryMinerItems(fragment.Miner[:], -1)
				if err != nil {
					n.Logdown("info", "query the storage miner failed: "+err.Error())
					return "", err
				}
				peerid := base58.Encode([]byte(string(miner.PeerId[:])))
				n.Logdown("info", "will connect the peer: "+peerid)
				addr, ok := n.GetPeer(peerid)
				if !ok {
					n.Logdown("info", "not fount the peer: "+peerid)
					continue
				}
				n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Minute)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				_, err = n.ReadDataAction(ctx, addr.ID, string(fragment.Hash[:]), fragmentpath)
				if err != nil {
					n.Peerstore().ClearAddrs(addr.ID)
					n.Logdown("info", " ReadDataAction failed: "+err.Error())
					continue
				}
				n.Peerstore().ClearAddrs(addr.ID)
			} else {
				_, err = os.Stat(fragmentpath)
				if err != nil {
					ff, _ := os.Create(fragmentpath)
					ff.Write(make([]byte, sconfig.FragmentSize))
					ff.Close()
				}
			}
		}
		segmentpath := filepath.Join(savedir, string(segment.Hash[:]))
		err = erasure.RSRestore(segmentpath, fragmentpaths)
		if err != nil {
			return "", err
		}
		segmentspath = append(segmentspath, segmentpath)
	}

	if len(segmentspath) != len(fmeta.SegmentList) {
		return "", errors.New("download failed")
	}
	var writecount = 0
	for i := 0; i < len(segmentspath); i++ {
		buf, err := os.ReadFile(segmentspath[i])
		if err != nil {
			fmt.Println("segmentspath not equal fmeta segmentspath")
			os.Exit(0)
		}
		if (writecount + 1) >= len(fmeta.SegmentList) {
			f.Write(buf[:(fmeta.FileSize.Uint64() - uint64(writecount*sconfig.SegmentSize))])
		} else {
			f.Write(buf)
		}
		writecount++
	}
	if writecount != len(fmeta.SegmentList) {
		return "", errors.New("write failed")
	}
	err = f.Sync()
	return userfile, err
}
