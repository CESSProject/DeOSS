/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/CESSProject/p2p-go/core"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/mr-tron/base58"
)

func (n *Node) syncFiles(ch chan<- bool) {
	defer func() {
		ch <- true
	}()
	var err error
	var data []byte
	var pubkey []byte
	var size int64
	var wantfiles = make([]wantFile, 0)
	var ossinfo pattern.OssInfo

	for {
		data, err = n.Get([]byte(Cache_WantFiles))
		if err != nil {
			if !errors.Is(err, db.NotFound) {
				n.Log("err", err.Error())
				time.Sleep(pattern.BlockInterval)
			} else {
				time.Sleep(time.Minute)
			}
			continue
		}
		err = json.Unmarshal(data, &wantfiles)
		if err != nil {
			n.Log("err", err.Error())
			time.Sleep(pattern.BlockInterval)
			continue
		}
		for i := 0; i < len(wantfiles); i++ {
			_, err = os.Stat(filepath.Join(n.GetDirs().FileDir, wantfiles[i].File))
			if err == nil {
				continue
			}
			pubkey, err = sutils.ParsingPublickey(wantfiles[i].Operator)
			if err != nil {
				n.Log("err", err.Error())
				continue
			}

			ossinfo, err = n.QueryDeOSSInfo(pubkey)
			if err != nil {
				n.Log("err", err.Error())
				continue
			}

			addr, ok := n.GetPeer(base58.Encode([]byte(string(ossinfo.Peerid[:]))))
			if !ok {
				continue
			}

			if n.ID().Pretty() == addr.ID.Pretty() {
				continue
			}

			err = n.Connect(n.GetCtxQueryFromCtxCancel(), addr)
			if err != nil {
				continue
			}
			var fragmentlist []pattern.FileHash
			fmeta, err := n.QueryFileMetadata(wantfiles[i].File)
			if err != nil {
				n.Log("err", err.Error())
				sorder, err := n.QueryStorageOrder(wantfiles[i].File)
				if err != nil {
					n.Log("err", err.Error())
					continue
				} else {
					size = sorder.FileSize.Int64()
					for _, segment := range sorder.SegmentList {
						fragmentlist = append(fragmentlist, segment.FragmentHash...)
					}
				}
			} else {
				size = fmeta.FileSize.Int64()
				for _, segment := range fmeta.SegmentList {
					for _, fragment := range segment.FragmentList {
						fragmentlist = append(fragmentlist, fragment.Hash)
					}
				}
			}

			//
			for _, fragment := range fragmentlist {
				fid, err := n.FidToCid(string(fragment[:]))
				if err != nil {
					n.Block("err", fmt.Sprintf("[FidToCid] [%v] %v", string(fragment[:]), err))
					continue
				}
				buf, err := n.getBlockData(fid)
				if err != nil {
					n.Block("err", fmt.Sprintf("[getBlockData] [%v] %v", fid, err))
					continue
				}
				n.Block("info", fmt.Sprintf("[%v] get block data suc", fid))
				n.SaveAndNotifyDataBlock(buf)
			}

			err = n.ReadDataAction(addr.ID, wantfiles[i].File, wantfiles[i].File, filepath.Join(n.GetDirs().FileDir, wantfiles[i].File), size)
			if err != nil {
				n.Block("err", fmt.Sprintf("[ReadDataAction] [%v] %v", wantfiles[i].File, err))
			}
		}
	}
}

func (n *Node) noticeBlocks(ch chan<- bool) {
	defer func() {
		time.Sleep(time.Minute * 2)
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Block("info", ">>>>> start noticyBlocks <<<<<")

	blockdirs, err := utils.DirDirs(filepath.Join(n.Workspace(), core.FileBlockDir), 0)
	if err != nil {
		n.Block("err", fmt.Sprintf("[DirDirs] [%v] %v", filepath.Join(n.Workspace(), core.FileBlockDir), err))
		time.Sleep(time.Minute)
		return
	}

	if len(blockdirs) == 0 {
		time.Sleep(time.Minute)
		return
	}

	for i := 0; i < len(blockdirs); i++ {
		datadir := filepath.Join(blockdirs[i], ".data")
		hash, err := sutils.CalcPathSHA256(datadir)
		if err != nil {
			n.Block("err", fmt.Sprintf("[CalcPathSHA256] [%v] %v", datadir, err))
			continue
		}
		mycid, err := n.FidToCid(hash)
		if err != nil {
			n.Block("err", fmt.Sprintf("[FidToCid] [%v] %v", hash, err))
			continue
		}

		acid, err := cid.Parse(mycid)
		if err != nil {
			n.Block("err", fmt.Sprintf("[cid.Parse(%s)] %v", mycid, err))
			continue
		}

		ok, err := n.GetBlockstore().Has(context.Background(), acid)
		if err == nil && ok {
			continue
		}

		buf, err := n.GetLocalDataFromBlock(mycid)
		if err != nil {
			n.Block("err", fmt.Sprintf("[GetLocalDataFromBlock] [%v] %v", mycid, err))
			continue
		}

		var blockData = blocks.NewBlock(buf)
		err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData)
		if err != nil {
			n.Block("err", fmt.Sprintf("[Blockstore.Put] %v", err))
			continue
		}

		err = n.GetBitSwap().NotifyNewBlocks(n.GetCtxQueryFromCtxCancel(), blockData)
		if err != nil {
			n.Block("err", fmt.Sprintf("[NotifyNewBlocks] [%v] %v", mycid, err))
			continue
		}

		n.Block("info", fmt.Sprintf("[NotifyNewBlocks] [%s] [%v] ", hash, mycid))
	}
}

func (n *Node) getBlockData(wantcid string) ([]byte, error) {
	fmt.Println("Will GetDataFromBlock ", wantcid)
	acid, err := cid.Decode(wantcid)
	if err != nil {
		fmt.Println("[cid.Decode] err: ", err)
		return nil, err
	}
	ctxTout, cancelFunc := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancelFunc()
	buf, err := n.GetBitSwap().GetBlock(ctxTout, acid)
	if err != nil {
		fmt.Println("GetBlock ", wantcid, " err: ", err)
		return nil, err
	}
	fmt.Println("GetBlock ", wantcid, " suc")
	return buf.RawData(), nil
}
