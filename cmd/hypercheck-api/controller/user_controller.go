// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package controller

import (
	"encoding/json"
	"net/http"

	"github.com/euskadi31/go-server"
	"github.com/gorilla/mux"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/storage"
	"github.com/hyperscale/hypercheck/types"
	"github.com/justinas/alice"
	"github.com/rs/zerolog/log"
)

// UserController struct
type UserController struct {
	userStorage    storage.UserStorage
	authMiddleware func(http.Handler) http.Handler
}

// NewUserController constructor
func NewUserController(userStorage storage.UserStorage, authMiddleware func(http.Handler) http.Handler) *UserController {
	return &UserController{
		userStorage:    userStorage,
		authMiddleware: authMiddleware,
	}
}

// Mount endpoints
func (c UserController) Mount(r *server.Router) {
	chain := alice.New(c.authMiddleware)

	r.AddRouteFunc("/users", c.postUserHandler).Methods(http.MethodPost)
	r.AddRoute("/users/{id:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}}", chain.ThenFunc(c.getUserHandler)).Methods(http.MethodGet)
}

func (c UserController) postUserHandler(w http.ResponseWriter, r *http.Request) {
	user := &types.User{}

	if err := json.NewDecoder(r.Body).Decode(user); err != nil {
		log.Error().Err(err).Msg("Unmarshal Request body failed")

		server.FailureFromError(w, http.StatusBadRequest, err)

		return
	}

	if err := c.userStorage.Create(user); err != nil {
		log.Error().Err(err).Msg("Create User failed")

		server.FailureFromError(w, http.StatusBadRequest, err)

		return
	}

	// clean password
	user.Password = ""

	server.JSON(w, http.StatusCreated, user)
}

func (c UserController) getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	user, err := c.userStorage.GetByID(id)
	if err != nil {
		log.Error().Err(err).Msg("Get User failed")

		server.FailureFromError(w, http.StatusNotFound, err)

		return
	}

	user.Password = ""

	server.JSON(w, http.StatusOK, user)
}
