// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storage

import (
	"time"

	"github.com/asdine/storm"
	"github.com/euskadi31/go-std"
	"github.com/hyperscale/hypercheck/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// UserStorage interface
type UserStorage interface {
	Create(user *types.User) error
	FindByEmail(email string) (*types.User, error)
	GetByID(id string) (*types.User, error)
}

type userStorage struct {
	db *storm.DB
}

// NewUserStorage constructor
func NewUserStorage(db *storm.DB) UserStorage {
	if err := db.Init(&types.User{}); err != nil {
		log.Fatal().Err(err).Msg("Initialize bucket for User")
	}

	return &userStorage{
		db: db,
	}
}

func (s *userStorage) Create(user *types.User) error {
	user.ID = uuid.NewV4().String()
	user.CreatedAt = std.DateTimeFrom(time.Now().UTC())

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "bcrypt.GenerateFromPassword failed")
	}

	user.Password = string(hash)

	log.Debug().Msgf("User: %#v", user)

	return s.db.Save(user)
}

func (s *userStorage) FindByEmail(email string) (*types.User, error) {
	user := &types.User{}

	if err := s.db.One("Email", email, user); err != nil {
		return nil, errors.Wrapf(err, "Cannot find user by email: %s", email)
	}

	return user, nil
}

func (s *userStorage) GetByID(id string) (*types.User, error) {
	user := &types.User{}

	if err := s.db.One("ID", id, user); err != nil {
		return nil, err
	}

	return user, nil
}
