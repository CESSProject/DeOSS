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
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-libipfs/blocks"
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

			ossinfo, err = n.QueryDeossInfo(pubkey)
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

			fmeta, err := n.QueryFileMetadata(wantfiles[i].File)
			if err != nil {
				n.Log("err", err.Error())
				sorder, err := n.QueryStorageOrder(wantfiles[i].File)
				if err != nil {
					n.Log("err", err.Error())
					continue
				} else {
					size = sorder.FileSize.Int64()
				}
			} else {
				size = fmeta.FileSize.Int64()
			}

			err = n.ReadDataAction(addr.ID, wantfiles[i].File, wantfiles[i].File, filepath.Join(n.GetDirs().FileDir, wantfiles[i].File), size)
			if err != nil {
				n.Log("err", err.Error())
			}
		}
	}
}

func (n *Node) getBlocks(ch chan<- bool) {
	defer func() {
		ch <- true
	}()

	time.Sleep(time.Second * 30)

	var wantList = []string{
		// 256k
		//"QmXeE7NjTLviHDaf7ZvWhdTW2P43QY41DgxpeogQeBXnoZ",
		// 1M
		"QmRdTXKPV8VPCuPaawjJZZaACsDYRfVtZtNZTDLXrAQPx3",
		// 2M
		"QmU9TPr52YZPngKq3AG21FfFztgfsW3LQQKnUWvF73fZjT",
		// 3M
		"QmayoE5xG6tvgzTp2bZNErk7TSHW8ou4FKv2mamtGLNpMi",
		// 3.5M
		"QmTZciSbB99gqWZknzcZ1HFFtbpnnEz4LTpxQe7zxBmpTF",
		// 4M
		"Qmay44Rd1U2Gcg3WB2BgTCezP9LNqrTzeDUZt2LKb7HSFh",
		// 6M
		"QmadWN69GhfNWtuobno9v1XhXWjSfLkRXEdL32W4gaYunb",
		// 8M
		"QmRQyZGdTjS2bYy1BisteG41NtWFSWTjE3smueqQpNZady",
		// 10M
		"QmdoP3JcdjeWXFDUrsvL3rqKejZJrRaBEEUEHyKwW6JV96",
		// 12M
		"QmcKLqao5TcawyJdtDRFbHvMc1ktfepjpqXuu62o6ve1bx",
		// 6Bytes
		//"QmXsMQRrggM1pD2axFoscGSrANph6f1nsQm6oFm3AHzECy",
		// 16M
		// "QmcfxLnapUJbDXN68zTYQZX5eaCZ3nSqeG5PFwDCThRwnP",
		// "QmauZXKtvXaz7j3Kqq3wA2NURgmJTQL5o8T4N5YProYzt8",
		// "QmVLsR4VH3AwEMf9mvBhBGgcQcKLyjQdekJPKHXHWgVF4c",
		// "Qma9hBSf9FobnK8N3cLxUuGHtMZfd4b2a66jCVQtYe5CHr",
		// "QmdoJangkxFUQsMrvAsmN4vZVHUHqpREJfmbrSHk6XAsDm",
		// "QmQUnEaKsHNLteYcQJDNVaHHV243sq8uWU6pVpQUbrSq1P",
		// "QmWo6MkkYmKzToPzkXQu2aTS3vQj21fHQiFc3G3jNTzzWT",
		// "QmUoJN78mHiCETZv3oRLLYSPAKfgWWgGvw18kCfF5TFH3d",
		// "QmXPKrreCAhPMixUFQmCerAvNaMe2rDMqgzjaVrQTqocgZ",
		// "QmYgYQSPeQuGxuQutsAoikYWXA7wmakQuUcqcLNuMGV6Y7",
		// "QmfDcKHD6PuWfhZJPxaSBVCbmBzxnKzzNroUJoyncqL6Eq",
		// "QmT3Pe3wiWpGpcYu4ANuSizzB3463svxSTz1VaqT276vrs",
		// "QmV5TvFzDBfVmo8vyweVBvaNeHESdnUss81QEuKm5EeMdQ",
		// "QmX3yLqBH78MHNmYjSR27vwGidFH8XYZ96zAYAZLdSkZxj",
		// "QmZotvwGTFSaLaSueeLdWuvHgzpYY4d9g2L6ZdX2BpkE9V",
		// "QmaqYqCLiEWdXdsV2HJdsTqfEJGUgk6Tbv8FDmhPcKsjm9",
		// "QmP5ya9sCaMJDvMJKGXNAxfiS73DKm477nuvG6LwHBbQfz",
		// "QmR9GRtE6JypMbQ8BD4bjAfETGuursZ5Q4GiTLppx5u7kc",
	}
	for i := 0; i < len(wantList); i++ {
		_, err := n.getBlockData(wantList[i])
		if err != nil {
			fmt.Println(err)
		}
	}
}

func (n *Node) noticyBlocks(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	//n.Discover("info", ">>>>> start discoverMgt <<<<<")
	fmt.Println("Start syncBlocks")
	var ok bool
	var blockMap = make(map[string]*blocks.BasicBlock, 0)

	// // 1M
	// data_1M := make([]byte, 1024*1024)
	// var blockData1M = blocks.NewBlock(data_1M)
	// err := n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData1M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 1M data cid: ", blockData1M.Cid().String())
	// blockMap[blockData1M.Cid().String()] = blockData1M

	// // 2M
	// data_2M := make([]byte, 2*1024*1024)
	// var blockData2M = blocks.NewBlock(data_2M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData2M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 2M data cid: ", blockData2M.Cid().String())
	// blockMap[blockData2M.Cid().String()] = blockData2M

	// // 3M
	// data_3M := make([]byte, 3*1024*1024)
	// var blockData3M = blocks.NewBlock(data_3M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData3M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 3M data cid: ", blockData3M.Cid().String())
	// blockMap[blockData3M.Cid().String()] = blockData3M

	// // 3.5M
	// data_3_5M := make([]byte, 7*1024*1024/2)
	// var blockData3_5M = blocks.NewBlock(data_3_5M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData3_5M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 3.5M data cid: ", blockData3_5M.Cid().String())
	// blockMap[blockData3_5M.Cid().String()] = blockData3_5M

	// // 4M
	// data_4M := make([]byte, 4*1024*1024)
	// var blockData4M = blocks.NewBlock(data_4M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData4M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 4M data cid: ", blockData4M.Cid().String())
	// blockMap[blockData4M.Cid().String()] = blockData4M

	// // 6M
	// data_6M := make([]byte, 6*1024*1024)
	// var blockData6M = blocks.NewBlock(data_6M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData6M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 6M data cid: ", blockData6M.Cid().String())
	// blockMap[blockData6M.Cid().String()] = blockData6M

	// // 8M
	// data_8M := make([]byte, 8*1024*1024)
	// var blockData8M = blocks.NewBlock(data_8M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData8M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 8M data cid: ", blockData8M.Cid().String())
	// blockMap[blockData8M.Cid().String()] = blockData8M

	// // 10M
	// data_10M := make([]byte, 10*1024*1024)
	// var blockData10M = blocks.NewBlock(data_10M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData10M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 10M data cid: ", blockData10M.Cid().String())
	// blockMap[blockData10M.Cid().String()] = blockData10M

	// // 12M
	// data_12M := make([]byte, 12*1024*1024)
	// var blockData12M = blocks.NewBlock(data_12M)
	// err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData12M)
	// if err != nil {
	// 	fmt.Println("[Put] err: ", err)
	// 	return
	// }
	// fmt.Println(">>> gen a new 12M data cid: ", blockData12M.Cid().String())
	// blockMap[blockData12M.Cid().String()] = blockData12M

	for {
		blockdirs, err := utils.DirDirs(filepath.Join(n.Workspace(), core.FileBlockDir), 0)
		if err != nil {
			fmt.Println("[noticyBlocks.DirDirs] err: ", err)
			return
		}

		for i := 0; i < len(blockdirs); i++ {
			datadir := filepath.Join(blockdirs[i], ".data")
			fmt.Println("[datadir]: ", datadir)
			hash, err := sutils.CalcPathSHA256(datadir)
			if err != nil {
				fmt.Println("[CalcPathSHA256] err: ", err)
				continue
			}
			mycid, err := n.FidToCid(hash)
			if err != nil {
				fmt.Println("[FidToCid] err: ", err)
				continue
			}

			fmt.Println("Local cid: ", mycid)

			buf, err := n.GetLocalDataFromBlock(mycid)
			if err != nil {
				fmt.Println("[GetDataFromBlock] err: ", err)
				continue
			}
			var blockData = blocks.NewBlock(buf)

			err = n.GetBlockstore().Put(n.GetCtxQueryFromCtxCancel(), blockData)
			if err != nil {
				fmt.Println("[Put] err: ", err)
				continue
			}

			_, ok = blockMap[mycid]
			if !ok {
				blockMap[mycid] = blockData
			}
		}

		if len(blockdirs) == 0 {
			fmt.Println("----Local block data is empty------")
			time.Sleep(time.Minute)
			return
		}

		count := 0
		for count <= 10 {
			for k, v := range blockMap {
				err = n.GetBitSwap().NotifyNewBlocks(n.GetCtxQueryFromCtxCancel(), v)
				if err != nil {
					fmt.Println("[NotifyNewBlocks] ", k, " err: ", err)
				} else {
					fmt.Println("[NotifyNewBlocks] ", k, " suc")
				}
				count++
			}
			time.Sleep(time.Second * 10)
		}
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
