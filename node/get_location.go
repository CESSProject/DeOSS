/*
Copyright (C) CESS. All rights reserved.
Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58/base58"
	ma "github.com/multiformats/go-multiaddr"
)

type NodeInfo struct {
	PeerId   string   `json:"peer_id"`
	Location Location `json:"location"`
}

type Location struct {
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
}

func (n *Node) Get_location(c *gin.Context) {
	fid := c.Param(HTTP_ParameterName_Fid)

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	n.Logopen("info", clientIp+" get location: "+fid)

	metadata, err := n.QueryFile(fid, -1)
	if err != nil {
		if errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
			c.JSON(404, "The file has not been stored in the storage miner yet, please check again later.")
			return
		}
		c.JSON(500, err.Error())
		return
	}
	length := sconfig.ParShards + sconfig.DataShards
	var data = make(map[string]NodeInfo, len(metadata.SegmentList))
	account := ""
	key := ""

	for j := 0; j < length; j++ {
		key = fmt.Sprintf("%d batch fragments", j)
		account, _ = sutils.EncodePublicKeyAsCessAccount(metadata.SegmentList[0].FragmentList[j].Miner[:])
		addr, peerid, err := n.getMinerAddr(account)
		if peerid == "" {
			minerInfo, err := n.QueryMinerItems(metadata.SegmentList[0].FragmentList[j].Miner[:], -1)
			if err == nil {
				peerid = base58.Encode([]byte(string(minerInfo.PeerId[:])))
			}
		}
		if err != nil {
			data[key] = NodeInfo{
				PeerId: peerid,
				Location: Location{
					Longitude: 0,
					Latitude:  0,
				},
			}
			continue
		}
		longitude, latitude, err := n.getAddrLocation(addr)
		if err != nil {
			data[key] = NodeInfo{
				PeerId: peerid,
				Location: Location{
					Longitude: 0,
					Latitude:  0,
				},
			}
			continue
		}
		data[key] = NodeInfo{
			PeerId: peerid,
			Location: Location{
				Longitude: longitude,
				Latitude:  latitude,
			},
		}
	}

	c.JSON(http.StatusOK, data)
}

func (n *Node) getMinerAddr(account string) (peer.AddrInfo, string, error) {
	addr, ok := n.GetPeerByAccount(account)
	if ok {
		return addr, "", nil
	}
	puk, err := sutils.ParsingPublickey(account)
	if err != nil {
		return peer.AddrInfo{}, "", err
	}
	minerInfo, err := n.QueryMinerItems(puk, -1)
	if err != nil {
		return peer.AddrInfo{}, "", err
	}
	peerid := base58.Encode([]byte(string(minerInfo.PeerId[:])))
	addr, ok = n.GetPeer(peerid)
	if ok {
		return addr, base58.Encode([]byte(string(minerInfo.PeerId[:]))), nil
	}
	return peer.AddrInfo{}, "", fmt.Errorf("not fount peer: %s", peerid)
}

func (n *Node) getAddrLocation(addr peer.AddrInfo) (float64, float64, error) {
	length := len(addr.Addrs)
	for i := 0; i < length; i++ {
		longitude, latitude, ok := n.parseCity(addr.Addrs[i].String())
		if ok {
			return longitude, latitude, nil
		}
	}
	return 0, 0, fmt.Errorf("not found location: %v", addr)
}

func (n *Node) parseCity(str string) (float64, float64, bool) {
	tmp := strings.Split(str, "/")
	for _, v := range tmp {
		ip := net.ParseIP(v)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		city, err := coordinate.GetCity(ip)
		if err == nil {
			return city.Location.Longitude, city.Location.Latitude, true
		}
	}
	return 0, 0, false
}

func (n *Node) getAddrsCoordinate(addrs []ma.Multiaddr) (coordinate.Coordinate, error) {
	length := len(addrs)
	for i := 0; i < length; i++ {
		longitude, latitude, ok := n.parseCity(addrs[i].String())
		if ok {
			return coordinate.Coordinate{Longitude: longitude, Latitude: latitude}, nil
		}
	}
	return coordinate.Coordinate{}, fmt.Errorf("not found coordinate: %v", addrs)
}
