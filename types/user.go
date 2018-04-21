// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package types

import (
	"github.com/euskadi31/go-std"
)

// User struct
type User struct {
	ID        string       `storm:"id" json:"id"`
	Email     string       `storm:"unique" json:"email"`
	FirstName std.String   `json:"firstname,omitempty"`
	LastName  std.String   `json:"lastname,omitempty"`
	Password  string       `json:"password,omitempty"`
	IsEnabled bool         `json:"enabled"`
	IsExpired bool         `json:"expired"`
	IsLocked  bool         `json:"locked"`
	Timezone  std.String   `json:"timezone,omitempty"`
	Locale    std.String   `json:"locale,omitempty"`
	CreatedAt std.DateTime `json:"created_at"`
	UpdatedAt std.DateTime `json:"updated_at"`
	DeletedAt std.DateTime `json:"deleted_at"`
}
