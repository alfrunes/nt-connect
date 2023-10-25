// Copyright 2021 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package model

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	wsft "github.com/mendersoftware/go-lib-micro/ws/filetransfer"
)

var (
	ErrChrootViolation = errors.New("the path is escaping chroot environment")
	ErrOverwriteFile   = errors.New("cannot overwrite file at destination")
)

func applyChroot(path, chroot string) (string, error) {
	var err error
	path = filepath.Join(chroot, path)
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(path, chroot) {
		return "", ErrChrootViolation
	}
	return path, nil
}

type UploadRequest wsft.UploadRequest

func (f UploadRequest) Validate() error {
	return validation.ValidateStruct(&f,
		validation.Field(&f.Path, validation.Required),
	)
}

func (f UploadRequest) DestinationPath(chroot string) (string, error) {
	if f.Path == nil {
		return "", errors.New("model: GetFile path not initialized")
	}
	var err error
	parent := filepath.Join(chroot, *f.Path)
	dst, err := filepath.EvalSymlinks(parent)
	if os.IsNotExist(err) {
		dst = parent
		parent = filepath.Dir(parent)
		parent, err = filepath.EvalSymlinks(parent)
		if err != nil {
			return "", err
		}
		fileInfo, err := os.Lstat(parent)
		if err != nil {
			return "", err
		} else if !fileInfo.IsDir() {
			return "", &fs.PathError{
				Path: parent,
				Op:   "UploadRequest.DestinationPath",
				Err:  os.ErrNotExist,
			}
		}
	} else if err != nil {
		return "", err
	} else {
		// dst exists, assert that the destination is a regular file.
		// If it is a directory, try to append the filename of f.SrcPath.
		fileInfo, err := os.Lstat(dst)
		if err != nil {
			return "", err
		}
		if fileInfo.IsDir() && f.SrcPath != nil {
			dst = filepath.Join(dst, filepath.Base(*f.SrcPath))
			fileInfo, err = os.Lstat(dst)
			if err == nil {
				if fileInfo.Mode()&os.ModeSymlink > 0 {
					dst, err = os.Readlink(dst)
					if err != nil {
						return "", err
					}
				} else if !fileInfo.Mode().IsRegular() {
					return "", &fs.PathError{
						Path: parent,
						Op:   "UploadRequest.DestinationPath",
						Err:  ErrOverwriteFile,
					}
				}
			} else if !os.IsNotExist(err) {
				return "", err
			}
		} else if !fileInfo.Mode().IsRegular() {
			return "", &fs.PathError{
				Path: parent,
				Op:   "UploadRequest.DestinationPath",
				Err:  ErrOverwriteFile,
			}
		}
	}
	if !strings.HasPrefix(parent, chroot) {
		return "", &fs.PathError{
			Path: dst,
			Op:   "UploadRequest.DestinationPath",
			Err:  ErrChrootViolation,
		}
	}
	return dst, nil
}

type StatFile wsft.StatFile

func (s StatFile) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.Path, validation.Required),
	)
}

func (f StatFile) AbsolutePath(chroot string) (string, error) {
	if f.Path == nil {
		return "", errors.New("model: GetFile path not initialized")
	}
	return applyChroot(*f.Path, chroot)
}

type GetFile wsft.GetFile

func (f GetFile) Validate() error {
	return validation.ValidateStruct(&f,
		validation.Field(&f.Path, validation.Required),
	)
}

func (f GetFile) AbsolutePath(chroot string) (string, error) {
	if f.Path == nil {
		return "", errors.New("model: GetFile path not initialized")
	}
	return applyChroot(*f.Path, chroot)
}
