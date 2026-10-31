// Package keys makes and checks the two credentials of the relay. Both are
// derived from one server secret, so the relay keeps no database:
//
//   - Hub token "prh_<hub id>.<mac>": the MAC is HMAC-SHA256 of the hub id.
//     A hub sends it on every push.
//   - Device handle "prd_<sealed>": the FCM token of one phone and the id of
//     the hub it signed in to, sealed with AES-256-GCM. The app gets it from
//     the relay and gives it to its hub, so the hub never sees the FCM token
//     and can push only to phones that enrolled with it.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	HubTokenPrefix = "prh_"
	HandlePrefix   = "prd_"

	hubIDLen      = 16 // random bytes in a hub id
	macLen        = 32
	handleVersion = 1
	maxFCMToken   = 4096
)

var (
	ErrBadToken  = errors.New("invalid hub token")
	ErrBadHandle = errors.New("invalid device handle")
	ErrBadHubID  = errors.New("invalid hub id")
)

var b64 = base64.RawURLEncoding

// Keys holds the keys derived from the server secret.
type Keys struct {
	mac  []byte
	aead cipher.AEAD
}

// New derives the keys from secret (at least 32 bytes).
func New(secret []byte) (*Keys, error) {
	if len(secret) < 32 {
		return nil, errors.New("secret must be at least 32 bytes")
	}
	macKey, err := hkdf.Key(sha256.New, secret, nil, "pingtxt-push-relay hub token v1", 32)
	if err != nil {
		return nil, err
	}
	encKey, err := hkdf.Key(sha256.New, secret, nil, "pingtxt-push-relay device handle v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Keys{mac: macKey, aead: aead}, nil
}

// NewHub makes a new random hub id and its token.
func (k *Keys) NewHub() (hubID, token string) {
	id := make([]byte, hubIDLen)
	rand.Read(id)
	hubID = b64.EncodeToString(id)
	return hubID, k.HubToken(hubID)
}

// HubToken returns the token of hubID.
func (k *Keys) HubToken(hubID string) string {
	return HubTokenPrefix + hubID + "." + b64.EncodeToString(k.sum(hubID))
}

func (k *Keys) sum(hubID string) []byte {
	m := hmac.New(sha256.New, k.mac)
	m.Write([]byte(hubID))
	return m.Sum(nil)
}

// CheckHubToken returns the hub id of a valid token.
func (k *Keys) CheckHubToken(token string) (string, error) {
	rest, ok := strings.CutPrefix(token, HubTokenPrefix)
	if !ok {
		return "", ErrBadToken
	}
	hubID, macStr, ok := strings.Cut(rest, ".")
	if !ok || ValidHubID(hubID) != nil {
		return "", ErrBadToken
	}
	mac, err := b64.DecodeString(macStr)
	if err != nil || len(mac) != macLen || !hmac.Equal(mac, k.sum(hubID)) {
		return "", ErrBadToken
	}
	return hubID, nil
}

// ValidHubID checks the shape of a hub id.
func ValidHubID(hubID string) error {
	raw, err := b64.DecodeString(hubID)
	if err != nil || len(raw) != hubIDLen {
		return ErrBadHubID
	}
	return nil
}

// SealDevice returns the handle of an FCM token enrolled with hubID.
func (k *Keys) SealDevice(hubID, fcmToken string) (string, error) {
	if ValidHubID(hubID) != nil {
		return "", ErrBadHubID
	}
	if fcmToken == "" || len(fcmToken) > maxFCMToken {
		return "", errors.New("invalid fcm token")
	}
	id, _ := b64.DecodeString(hubID)
	plain := make([]byte, 0, len(id)+len(fcmToken))
	plain = append(plain, id...)
	plain = append(plain, fcmToken...)

	nonce := make([]byte, k.aead.NonceSize())
	rand.Read(nonce)
	out := make([]byte, 0, 1+len(nonce)+len(plain)+k.aead.Overhead())
	out = append(out, handleVersion)
	out = append(out, nonce...)
	out = k.aead.Seal(out, nonce, plain, []byte{handleVersion})
	return HandlePrefix + b64.EncodeToString(out), nil
}

// OpenDevice returns the FCM token sealed in handle, only if the handle
// belongs to hubID.
func (k *Keys) OpenDevice(hubID, handle string) (string, error) {
	rest, ok := strings.CutPrefix(handle, HandlePrefix)
	if !ok {
		return "", ErrBadHandle
	}
	raw, err := b64.DecodeString(rest)
	ns := k.aead.NonceSize()
	if err != nil || len(raw) < 1+ns+hubIDLen+1+k.aead.Overhead() || raw[0] != handleVersion {
		return "", ErrBadHandle
	}
	plain, err := k.aead.Open(nil, raw[1:1+ns], raw[1+ns:], []byte{handleVersion})
	if err != nil {
		return "", ErrBadHandle
	}
	id, err := b64.DecodeString(hubID)
	if err != nil || !hmac.Equal(id, plain[:hubIDLen]) {
		return "", ErrBadHandle
	}
	return string(plain[hubIDLen:]), nil
}
