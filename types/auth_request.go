// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package types

// AuthRequest struct
type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate auth request
func (r AuthRequest) Validate() bool {
	return r.Email != "" && r.Password != ""
}
