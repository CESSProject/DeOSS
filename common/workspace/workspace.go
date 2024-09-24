/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	fileDir    = "file"
	storingDir = "storing"
	tmpDir     = "tmp"
	logDir     = "log"
	trackDir   = "track"
)

type Workspace interface {
	Build() error
	RemoveAndBuild() error
	GetRootDir() string
	GetFileDir() string
	GetStoringDir() string
	GetTmpDir() string
	GetLogDir() string
	GetTrackDir() string
}

type workspace struct {
	rootDir    string
	fileDir    string
	storingDir string
	tmpDir     string
	logDir     string
	trackDir   string
}

var _ Workspace = (*workspace)(nil)

func NewWorkspace(ws string) Workspace {
	return &workspace{rootDir: ws}
}

func (w *workspace) RemoveAndBuild() error {
	if w.rootDir == "" {
		return fmt.Errorf("Please initialize the workspace first")
	}

	w.fileDir = filepath.Join(w.rootDir, fileDir)
	w.storingDir = filepath.Join(w.rootDir, storingDir)
	w.tmpDir = filepath.Join(w.rootDir, tmpDir)
	w.logDir = filepath.Join(w.rootDir, logDir)
	w.trackDir = filepath.Join(w.rootDir, trackDir)

	err := os.RemoveAll(w.fileDir)
	if err != nil {
		return err
	}
	err = os.RemoveAll(w.storingDir)
	if err != nil {
		return err
	}
	err = os.RemoveAll(w.tmpDir)
	if err != nil {
		return err
	}
	err = os.RemoveAll(w.logDir)
	if err != nil {
		return err
	}
	err = os.RemoveAll(w.trackDir)
	if err != nil {
		return err
	}

	err = os.MkdirAll(w.fileDir, 0755)
	if err != nil {
		return err
	}

	err = os.MkdirAll(w.storingDir, 0755)
	if err != nil {
		return err
	}

	err = os.MkdirAll(w.tmpDir, 0755)
	if err != nil {
		return err
	}

	err = os.MkdirAll(w.trackDir, 0755)
	if err != nil {
		return err
	}

	return os.MkdirAll(w.logDir, 0755)
}

func (w *workspace) Build() error {
	if w.rootDir == "" {
		return fmt.Errorf("Please initialize the workspace first")
	}

	w.logDir = filepath.Join(w.rootDir, logDir)
	if err := os.MkdirAll(w.logDir, 0755); err != nil {
		return err
	}

	w.fileDir = filepath.Join(w.rootDir, fileDir)
	if err := os.MkdirAll(w.fileDir, 0755); err != nil {
		return err
	}

	w.storingDir = filepath.Join(w.rootDir, storingDir)
	if err := os.MkdirAll(w.storingDir, 0755); err != nil {
		return err
	}

	w.tmpDir = filepath.Join(w.rootDir, tmpDir)
	if err := os.MkdirAll(w.tmpDir, 0755); err != nil {
		return err
	}

	w.trackDir = filepath.Join(w.rootDir, trackDir)
	if err := os.MkdirAll(w.trackDir, 0755); err != nil {
		return err
	}
	return nil
}

func (w *workspace) GetRootDir() string {
	return w.rootDir
}
func (w *workspace) GetFileDir() string {
	return w.fileDir
}
func (w *workspace) GetStoringDir() string {
	return w.storingDir
}
func (w *workspace) GetTmpDir() string {
	return w.tmpDir
}
func (w *workspace) GetLogDir() string {
	return w.logDir
}
func (w *workspace) GetTrackDir() string {
	return w.trackDir
}
