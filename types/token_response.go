// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package types

// TokenResponse response
type TokenResponse struct {
	Value   string `json:"token"`
	Expires int64  `json:"expires"`
}
