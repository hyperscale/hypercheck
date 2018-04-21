// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authenticate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/storage"
	"github.com/hyperscale/hypercheck/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	privateKey = "private.pem"
	publicKey  = "public.pem"
)

// JWTProvider struct
type JWTProvider struct {
	path        string
	userStorage storage.UserStorage
	privateKey  []byte
	publicKey   []byte
}

// NewJWTProvider func
func NewJWTProvider(path string, userStorage storage.UserStorage) *JWTProvider {
	return &JWTProvider{
		path:        strings.TrimRight(path, "/"),
		userStorage: userStorage,
	}
}

func (s *JWTProvider) savePrivatePEMKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(fmt.Sprintf("%s/%s", s.path, filename))
	if err != nil {
		return errors.Wrap(err, "os.Create")
	}
	defer file.Close()

	var privateKey = &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.Encode(file, privateKey)
}

func (s *JWTProvider) savePublicPEMKey(filename string, pubkey rsa.PublicKey) error {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	//asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return errors.Wrap(err, "x509.MarshalPKIXPublicKey")
	}

	var pemkey = &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   asn1Bytes,
	}

	file, err := os.Create(fmt.Sprintf("%s/%s", s.path, filename))
	if err != nil {
		return errors.Wrap(err, "os.Create")
	}
	defer file.Close()

	return pem.Encode(file, pemkey)
}

// HasKey exists
func (s *JWTProvider) HasKey() bool {
	if _, err := os.Stat(fmt.Sprintf("%s/%s", s.path, privateKey)); os.IsNotExist(err) {
		return false
	}

	if _, err := os.Stat(fmt.Sprintf("%s/%s", s.path, publicKey)); os.IsNotExist(err) {
		return false
	}

	return true
}

// LoadKeys files
func (s *JWTProvider) LoadKeys() error {
	bytes, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", s.path, privateKey))
	if err != nil {
		return errors.Wrap(err, "ioutil.ReadFile")
	}

	s.privateKey = bytes

	bytes, err = ioutil.ReadFile(fmt.Sprintf("%s/%s", s.path, publicKey))
	if err != nil {
		return errors.Wrap(err, "ioutil.ReadFile")
	}

	s.publicKey = bytes

	return nil
}

// GenerateKey files in path
func (s *JWTProvider) GenerateKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	if err := s.savePrivatePEMKey(privateKey, key); err != nil {
		return errors.Wrap(err, "savePrivatePEMKey")
	}

	if err := s.savePublicPEMKey(publicKey, key.PublicKey); err != nil {
		return errors.Wrap(err, "savePublicPEMKey")
	}

	return nil
}

// GenerateToken string
func (s *JWTProvider) GenerateToken(claims jws.Claims) (string, error) {
	rsaPrivate, err := crypto.ParseRSAPrivateKeyFromPEM(s.privateKey)
	if err != nil {
		return "", errors.Wrap(err, "crypto.ParseRSAPrivateKeyFromPEM")
	}

	//jwt := jws.NewJWT(claims, crypto.SigningMethodHS256)
	jwt := jws.NewJWT(claims, crypto.SigningMethodRS256)

	b, err := jwt.Serialize(rsaPrivate)
	if err != nil {
		return "", errors.Wrap(err, "jwt.Serialize")
	}

	return string(b), nil
}

// Validate token
func (s *JWTProvider) Validate(r *http.Request) bool {
	authorization := r.Header.Get("Authorization")

	if len(authorization) <= 7 {
		log.Error().Msg("Authorization header invalid")

		return false
	}

	return s.ValidateToken(authorization[7:])
}

// ValidateToken token
func (s *JWTProvider) ValidateToken(token string) bool {
	rsaPublic, err := crypto.ParseRSAPublicKeyFromPEM(s.publicKey)
	if err != nil {
		log.Error().Err(err).Msg("crypto.ParseRSAPublicKeyFromPEM")

		return false
	}

	jwt, err := jws.ParseJWT([]byte(token))
	if err != nil {
		log.Error().Err(err).Msg("jws.ParseJWT")

		return false
	}

	// Validate token
	if err = jwt.Validate(rsaPublic, crypto.SigningMethodRS256); err != nil {
		log.Error().Err(err).Msg("jwt.Validate")

		return false
	}

	return true
}

// Authenticate user
func (s *JWTProvider) Authenticate(req *types.AuthRequest) (*types.TokenResponse, error) {
	if !req.Validate() {
		return nil, errors.New("username or password is incorrect")
	}

	user, err := s.userStorage.FindByEmail(req.Email)
	if err != nil {
		return nil, errors.Wrap(err, "userStorage.FindByEmail")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, errors.Wrap(err, "bcrypt.CompareHashAndPassword")
	}

	expiration := time.Now().Add(time.Duration(2) * time.Hour)

	claims := jws.Claims{}
	claims.SetIssuer("Hypercheck")
	claims.SetSubject(user.ID)
	claims.SetExpiration(expiration)
	claims.SetIssuedAt(time.Now().UTC())
	claims.SetJWTID(uuid.NewV4().String())

	token, err := s.GenerateToken(claims)
	if err != nil {
		return nil, errors.Wrap(err, "GenerateToken")
	}

	return &types.TokenResponse{
		Value:   token,
		Expires: expiration.Unix(),
	}, nil
}
