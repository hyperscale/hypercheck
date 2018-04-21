// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package controller

import (
	"encoding/json"
	"net/http"

	"github.com/euskadi31/go-server"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/authenticate"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/storage"
	"github.com/hyperscale/hypercheck/types"
	"github.com/rs/zerolog/log"
)

// AuthController struct
type AuthController struct {
	userStorage  storage.UserStorage
	authProvider *authenticate.JWTProvider
}

// NewAuthController constructor
func NewAuthController(userStorage storage.UserStorage, authProvider *authenticate.JWTProvider) *AuthController {
	return &AuthController{
		userStorage:  userStorage,
		authProvider: authProvider,
	}
}

// Mount endpoints
func (c AuthController) Mount(r *server.Router) {
	r.AddRouteFunc("/authenticate", c.postAuthenticateHandler).Methods(http.MethodPost)
}

func (c AuthController) postAuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	req := &types.AuthRequest{}

	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		log.Error().Err(err).Msg("Unmarshal Request body failed")

		server.FailureFromError(w, http.StatusBadRequest, err)

		return
	}

	resp, err := c.authProvider.Authenticate(req)
	if err != nil {
		log.Error().Err(err).Msg("Authenticate failed")

		server.FailureFromError(w, http.StatusBadRequest, err)

		return
	}

	server.JSON(w, http.StatusOK, resp)
}
