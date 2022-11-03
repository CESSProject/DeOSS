package db

import (
	"cess-gateway/configs"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	// minCache is the minimum amount of memory in megabytes to allocate to leveldb
	minCache = 16

	// minHandles is the minimum number of files handles to allocate to the open
	// database files.
	minHandles = 16
)

type LevelDB struct {
	fn string
	db *leveldb.DB
}

var c Cache

func GetDB() (Cache, error) {
	var err error
	if c == nil {
		_, err = os.Stat(configs.DbDir)
		if err != nil {
			err = os.MkdirAll(configs.DbDir, os.ModeDir)
			if err != nil {
				return nil, err
			}
		}
		c, err = newLevelDB(configs.DbDir, 0, 0, "cess-gateway")
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	if err = c.Delete([]byte("NIL")); err != nil {
		_, err = os.Stat(configs.DbDir)
		if err != nil {
			err = os.MkdirAll(configs.DbDir, os.ModeDir)
			if err != nil {
				return nil, err
			}
		}
		c, err = newLevelDB(configs.DbDir, 0, 0, "cess-gateway")
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return c, nil
}

func newLevelDB(file string, cache int, handles int, namespace string) (Cache, error) {
	options := configureOptions(cache, handles)
	db, err := leveldb.OpenFile(file, options)
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(file, nil)
	}
	if err != nil {
		return nil, err
	}

	ldb := &LevelDB{
		fn: file,
		db: db,
	}
	return ldb, nil
}

func configureOptions(cache int, handles int) *opt.Options {
	// Set default options
	options := &opt.Options{
		Filter:                 filter.NewBloomFilter(10),
		DisableSeeksCompaction: true,
	}
	if cache < minCache {
		cache = minCache
	}
	if handles < minHandles {
		handles = minHandles
	}
	// Set default options
	options.OpenFilesCacheCapacity = handles
	options.BlockCacheCapacity = cache / 2 * opt.MiB
	options.WriteBuffer = cache / 4 * opt.MiB // Two of these are used internally

	return options
}

func (db *LevelDB) Close() error {
	return db.db.Close()
}

func (db *LevelDB) Has(key []byte) (bool, error) {
	return db.db.Has(key, nil)
}

func (db *LevelDB) Get(key []byte) ([]byte, error) {
	dat, err := db.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

func (db *LevelDB) Put(key []byte, value []byte) error {
	return db.db.Put(key, value, nil)
}

func (db *LevelDB) Delete(key []byte) error {
	return db.db.Delete(key, nil)
}

func (db *LevelDB) Compact(start []byte, limit []byte) error {
	return db.db.CompactRange(util.Range{Start: start, Limit: limit})
}
