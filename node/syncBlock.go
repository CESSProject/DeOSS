/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

type userFiles struct {
	User  string   `json:"user"`
	Files []string `json:"files"`
}

type wantFile struct {
	Operator string `json:"operator"`
	File     string `json:"file"`
}

func (n *Node) syncBlock(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Block("info", ">>>>> start syncBlock <<<<<")

	var err error
	var blockheight uint32
	var retrievedBlock uint32
	var blockhash types.Hash

	data, err := n.Get([]byte(Cache_SyncBlock))
	if err != nil {
		if errors.Is(err, db.NotFound) {
			retrievedBlock = 200
		}
	}

	if retrievedBlock == 0 {
		time.Sleep(time.Millisecond * 10)
		data, err = n.Get([]byte(Cache_SyncBlock))
		if err != nil {
			retrievedBlock = 200
		} else {
			block, err := strconv.Atoi(string(data))
			if err != nil {
				retrievedBlock = 200
			} else {
				retrievedBlock = uint32(block)
			}
		}
	}

	n.Block("info", fmt.Sprintf("retrieved block in cache: %d", retrievedBlock))

	data, err = os.ReadFile(filepath.Join(n.Workspace(), Cache_SyncBlock))
	if err == nil {
		block, err := strconv.Atoi(string(data))
		if err == nil {
			n.Block("info", fmt.Sprintf("retrieved block in file: %d", block))
			if uint32(block) > retrievedBlock {
				retrievedBlock = uint32(block)
			}
		}
	}

	for {
		blockheight, err = n.QueryBlockHeight("")
		if err != nil {
			n.Block("err", fmt.Sprintf("[QueryBlockHeight] %v", err))
			time.Sleep(pattern.BlockInterval)
			continue
		}
		break
	}

	n.Block("info", fmt.Sprintf("Blocks started to be retrieved: %v", retrievedBlock))
	n.Block("info", fmt.Sprintf("Current latest block: %v", blockheight))

	for {
		if retrievedBlock >= blockheight {
			blockheight, err = n.QueryBlockHeight("")
			if err != nil {
				n.Block("err", fmt.Sprintf("[QueryBlockHeight] %v", err))
				time.Sleep(pattern.BlockInterval)
				continue
			}
			n.Block("info", fmt.Sprintf("latest block: %v", blockheight))
			if retrievedBlock >= blockheight {
				time.Sleep(pattern.BlockInterval)
				continue
			}
		}

		blockhash, err = n.GetSubstrateAPI().RPC.Chain.GetBlockHash(uint64(retrievedBlock))
		if err != nil {
			n.Block("err", fmt.Sprintf("[GetBlockHash] %v", err))
			time.Sleep(pattern.BlockInterval)
			continue
		}
		n.Block("err", fmt.Sprintf("Start retrieving blocks: %v", retrievedBlock))
		uploadDeclaration, _ := n.RetrieveAllEvent_FileBank_UploadDeclaration(blockhash)
		if len(uploadDeclaration) > 0 {
			var wantfiles = make([]wantFile, 0)
			for i := 0; i < len(uploadDeclaration); i++ {
				wantfiles = append(wantfiles, wantFile{
					Operator: uploadDeclaration[i].Operator,
					File:     uploadDeclaration[i].Filehash,
				})
				data, err := n.Get([]byte(Cache_UserFiles + uploadDeclaration[i].Owner))
				if err != nil {
					if errors.Is(err, db.NotFound) {
						err = n.saveUserFileToDb(uploadDeclaration[i].Owner, uploadDeclaration[i].Filehash)
						if err != nil {
							n.Block("err", fmt.Sprintf("[saveUserFileToDb] %v", err))
						}
						continue
					} else {
						time.Sleep(time.Millisecond * 10)
						data, err = n.Get([]byte(Cache_UserFiles + uploadDeclaration[i].Owner))
						if err != nil {
							err = n.saveUserFileToFile(uploadDeclaration[i].Owner, uploadDeclaration[i].Filehash)
							if err != nil {
								n.Block("err", fmt.Sprintf("[saveUserFileToFile] %v", err))
							}
							continue
						}
					}
				}
				var ufileData userFiles
				err = json.Unmarshal(data, &ufileData)
				if err != nil {
					n.Block("err", fmt.Sprintf("[Unmarshal] %v", err))
					err = n.saveUserFileToFile(uploadDeclaration[i].Owner, uploadDeclaration[i].Filehash)
					if err != nil {
						n.Block("err", fmt.Sprintf("[saveUserFileToFile] %v", err))
					}
					continue
				}
				ufileData.Files = append(ufileData.Files, uploadDeclaration[i].Filehash)
				buf, err := json.Marshal(&ufileData)
				if err != nil {
					n.Block("err", fmt.Sprintf("[Marshal] %v", err))
					err = n.saveUserFileToFile(uploadDeclaration[i].Owner, uploadDeclaration[i].Filehash)
					if err != nil {
						n.Block("err", fmt.Sprintf("[saveUserFileToFile] %v", err))
					}
					continue
				}
				err = n.Put([]byte(Cache_UserFiles+uploadDeclaration[i].Owner), buf)
				if err != nil {
					n.Block("err", fmt.Sprintf("[Put] %v", err))
					err = n.saveUserFileToFile(uploadDeclaration[i].Owner, uploadDeclaration[i].Filehash)
					if err != nil {
						n.Block("err", fmt.Sprintf("[saveUserFileToFile] %v", err))
					}
				}
			}

			if len(wantfiles) > 0 {
				data, err := n.Get([]byte(Cache_WantFiles))
				if err != nil {
					if errors.Is(err, db.NotFound) {
						data, err = json.Marshal(&wantfiles)
						if err != nil {
							n.Block("err", fmt.Sprintf("[Put] %v", err))
						} else {
							n.Put([]byte(Cache_WantFiles), data)
						}
					}
				} else {
					var wantfiles_old = make([]wantFile, 0)
					err = json.Unmarshal(data, &wantfiles_old)
					if err != nil {
						n.Block("err", fmt.Sprintf("[Unmarshal] %v", err))
						data, err = json.Marshal(&wantfiles)
						if err != nil {
							n.Block("err", fmt.Sprintf("[Put] %v", err))
						} else {
							n.Put([]byte(Cache_WantFiles), data)
						}
					} else {
						wantfiles_old = append(wantfiles_old, wantfiles...)
						data, err = json.Marshal(&wantfiles_old)
						if err != nil {
							n.Block("err", fmt.Sprintf("[Put] %v", err))
						} else {
							n.Put([]byte(Cache_WantFiles), data)
						}
					}
				}
			}
		}

		fileDeleted, _ := n.RetrieveAllEvent_FileBank_DeleteFile(blockhash)
		if len(fileDeleted) > 0 {
			for i := 0; i < len(fileDeleted); i++ {
				data, err := n.Get([]byte(Cache_UserDeleteFiles + fileDeleted[i].Owner))
				if err != nil {
					if errors.Is(err, db.NotFound) {
						err = n.saveUserDeletedFileToDb(fileDeleted[i].Owner, fileDeleted[i].Filehash)
						if err != nil {
							n.Block("err", fmt.Sprintf("[saveUserDeletedFileToDb] %v", err))
						}
						continue
					} else {
						time.Sleep(time.Millisecond * 10)
						data, err = n.Get([]byte(Cache_UserDeleteFiles + fileDeleted[i].Owner))
						if err != nil {
							n.Block("err", fmt.Sprintf("[Get] %v", err))
							err = n.saveUserDeletedFileToFile(fileDeleted[i].Owner, fileDeleted[i].Filehash)
							if err != nil {
								n.Block("err", fmt.Sprintf("[saveUserDeletedFileToFile] %v", err))
							}
							continue
						}
					}
				}
				var ufileData userFiles
				err = json.Unmarshal(data, &ufileData)
				if err != nil {
					n.Block("err", fmt.Sprintf("[Unmarshal] %v", err))
					err = n.saveUserDeletedFileToFile(fileDeleted[i].Owner, fileDeleted[i].Filehash)
					if err != nil {
						n.Block("err", fmt.Sprintf("[saveUserDeletedFileToFile] %v", err))
					}
					continue
				}
				ufileData.Files = append(ufileData.Files, fileDeleted[i].Filehash)
				buf, err := json.Marshal(&ufileData)
				if err != nil {
					n.Block("err", fmt.Sprintf("[Marshal] %v", err))
					err = n.saveUserDeletedFileToFile(fileDeleted[i].Owner, fileDeleted[i].Filehash)
					if err != nil {
						n.Block("err", fmt.Sprintf("[saveUserDeletedFileToFile] %v", err))
					}
					continue
				}
				err = n.Put([]byte(Cache_UserDeleteFiles+fileDeleted[i].Owner), buf)
				if err != nil {
					n.Block("err", fmt.Sprintf("[Put] %v", err))
					err = n.saveUserDeletedFileToFile(fileDeleted[i].Owner, fileDeleted[i].Filehash)
					if err != nil {
						n.Block("err", fmt.Sprintf("[saveUserDeletedFileToFile] %v", err))
					}
				}
			}
		}
		n.Block("err", fmt.Sprintf("Finish retrieving blocks: %v", err))
		retrievedBlock++
		err = n.Put([]byte(Cache_SyncBlock), []byte(fmt.Sprintf("%v", retrievedBlock)))
		if err != nil {
			time.Sleep(time.Millisecond * 10)
			err = n.Put([]byte(Cache_SyncBlock), []byte(fmt.Sprintf("%v", retrievedBlock)))
			if err != nil {
				n.Block("err", fmt.Sprintf("[Put] %v", err))
				err = os.WriteFile(filepath.Join(n.Workspace(), Cache_SyncBlock), []byte(fmt.Sprintf("%v", retrievedBlock)), os.ModePerm)
				if err != nil {
					n.Block("err", fmt.Sprintf("[WriteFile] %v", err))
				}
			}
		}
	}
}

func (n *Node) saveUserFileToDb(owner, hash string) error {
	var ufileData userFiles
	ufileData.User = owner
	ufileData.Files = []string{hash}
	buf, err := json.Marshal(&ufileData)
	if err != nil {
		return err
	}
	return n.Put([]byte(Cache_UserFiles+owner), buf)
}

func (n *Node) saveUserDeletedFileToDb(owner, hash string) error {
	var ufileData userFiles
	ufileData.User = owner
	ufileData.Files = []string{hash}
	buf, err := json.Marshal(&ufileData)
	if err != nil {
		return err
	}
	return n.Put([]byte(Cache_UserDeleteFiles+owner), buf)
}

func (n *Node) saveUserFileToFile(owner, hash string) error {
	var ufileData userFiles
	userfile := filepath.Join(n.ufileDir, owner)
	data, err := os.ReadFile(userfile)
	if err != nil {
		ufileData.User = owner
		ufileData.Files = []string{hash}
		buf, err := json.Marshal(&ufileData)
		if err != nil {
			return err
		}
		return os.WriteFile(userfile, buf, os.ModePerm)
	}
	err = json.Unmarshal(data, &ufileData)
	if err != nil {
		return err
	}

	if ufileData.User != owner {
		err = os.Rename(userfile, filepath.Join(n.ufileDir, ufileData.User))
		if err != nil {
			return err
		}
		ufileData.User = owner
		ufileData.Files = []string{hash}
		buf, err := json.Marshal(&ufileData)
		if err != nil {
			return err
		}
		return os.WriteFile(userfile, buf, os.ModePerm)
	}
	ufileData.Files = append(ufileData.Files, hash)
	buf, err := json.Marshal(&ufileData)
	if err != nil {
		return err
	}
	return os.WriteFile(userfile, buf, os.ModePerm)
}

func (n *Node) saveUserDeletedFileToFile(owner, hash string) error {
	var ufileData userFiles
	userdeletedfile := filepath.Join(n.dfileDir, owner)
	data, err := os.ReadFile(userdeletedfile)
	if err != nil {
		ufileData.User = owner
		ufileData.Files = []string{hash}
		buf, err := json.Marshal(&ufileData)
		if err != nil {
			return err
		}
		return os.WriteFile(userdeletedfile, buf, os.ModePerm)
	}
	err = json.Unmarshal(data, &ufileData)
	if err != nil {
		return err
	}

	if ufileData.User != owner {
		err = os.Rename(userdeletedfile, filepath.Join(n.dfileDir, ufileData.User))
		if err != nil {
			return err
		}
		ufileData.User = owner
		ufileData.Files = []string{hash}
		buf, err := json.Marshal(&ufileData)
		if err != nil {
			return err
		}
		return os.WriteFile(userdeletedfile, buf, os.ModePerm)
	}
	ufileData.Files = append(ufileData.Files, hash)
	buf, err := json.Marshal(&ufileData)
	if err != nil {
		return err
	}
	return os.WriteFile(userdeletedfile, buf, os.ModePerm)
}
