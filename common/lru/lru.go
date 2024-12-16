package lru

import (
	"container/list"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/CESSProject/cess-go-sdk/chain"
)

type file struct {
	Path  string
	Size  int64
	Atimt int64
}

type LRUCache struct {
	capacity  uint64
	usedSpace uint64
	files     map[string]*list.Element
	lru       *list.List
	mu        *sync.Mutex
}

func NewLRUCache(capacity uint64) *LRUCache {
	return &LRUCache{
		mu:        new(sync.Mutex),
		capacity:  capacity,
		usedSpace: 0,
		files:     make(map[string]*list.Element),
		lru:       list.New(),
	}
}

func (c *LRUCache) InitCheck(dir string) error {
	fileinfos, err := DirAllFileInfo(dir)
	if err != nil {
		return err
	}

	sort.Slice(fileinfos, func(i, j int) bool {
		return fileinfos[i].Atimt > fileinfos[j].Atimt
	})

	length := len(fileinfos)
	for i := 0; i < length; i++ {
		elem := c.lru.PushBack(&file{Path: fileinfos[i].Path, Size: fileinfos[i].Size, Atimt: fileinfos[i].Atimt})
		c.files[fileinfos[i].Path] = elem
		c.usedSpace += uint64(fileinfos[i].Size)
		continue
	}
	c.checkDiskUsage()
	return nil
}

func (c *LRUCache) AccessFile(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("add to lru: %v", err)
	}

	fileSize := fileInfo.Size()

	if elem, exists := c.files[path]; exists {
		file := elem.Value.(*file)
		file.Atimt = time.Now().Unix()
		c.lru.MoveToFront(elem)
	} else {
		file := &file{Path: path, Size: fileSize, Atimt: time.Now().Unix()}
		elem := c.lru.PushFront(file)
		c.files[path] = elem
		c.usedSpace += uint64(fileSize)
		c.checkDiskUsage()
	}
	return nil
}

func (c *LRUCache) checkDiskUsage() {
	for c.usedSpace > c.capacity {
		c.evict()
	}
}

func (c *LRUCache) evict() {
	elem := c.lru.Back()
	if elem != nil {
		c.lru.Remove(elem)
		file := elem.Value.(*file)
		delete(c.files, file.Path)
		fileInfo, err := os.Stat(file.Path)
		if err == nil {
			c.usedSpace -= uint64(fileInfo.Size())
			os.Remove(file.Path)
		}
	}
}

func DirAllFileInfo(dir string) ([]file, error) {
	var rtndata = make([]file, 0)
	result, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil, err
	}
	for _, v := range result {
		f, err := os.Stat(v)
		if err != nil {
			continue
		}
		if f.IsDir() {
			continue
		}

		if len(filepath.Base(v)) != chain.FileHashLen {
			os.Remove(v)
			continue
		}
		linuxFileAttr, ok := f.Sys().(*syscall.Stat_t)
		if !ok {
			rtndata = append(rtndata, file{
				Path:  v,
				Size:  f.Size(),
				Atimt: f.ModTime().Unix(),
			})
		} else {
			rtndata = append(rtndata, file{
				Path:  v,
				Size:  f.Size(),
				Atimt: linuxFileAttr.Atim.Sec,
			})
		}
	}
	return rtndata, nil
}
