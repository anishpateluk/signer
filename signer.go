// Package signer is used to generate the OAuth signed requests and is built solely for the purpose of use in LTI requests.
// LTI doesn't need the full OAuth 1 roundtrip, it's basically single legged. We simply need the signing functions to authorize
// the requests (as per LTI spec).
package signer

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"ghe.iparadigms.com/Integrations/Signer/util"

	log "github.com/Sirupsen/logrus"
)

// ValidateSignature takes the URL, params and secret and generates a signature. It then pulls the signature from the params
// and compares what we created with what was passed in to determine whether it was correct or not.
func ValidateSignature(url string, form url.Values, secret string) bool {
	s := Signer{
		URL:    url,
		Secret: secret,
	}

	params := make(map[string]string)

	for k := range form {
		params[k] = form.Get(k)
	}

	in := params["oauth_signature"]

	// delete oauth signature from params since it's never used in generation
	delete(params, "oauth_signature")

	gen := s.signRequest(params)

	if in != gen {
		return false
	}

	return true
}

// SignedBodyRequest returns an http.Request with the body appended and a valid authorization header attached.
func SignedBodyRequest(method string, url string, key string, secret string, body string) (*http.Request, error) {
	if method == "" {
		method = "POST"
	}

	request, _ := http.NewRequest(method, url, strings.NewReader(body))

	s := NewSigner(method, url, key, secret, body, nil)

	h, err := s.BuildAuthHeader()
	if err != nil {
		return nil, err
	}

	request.Header.Add("Authorization", h)

	return request, nil
}

// SignedFormRequest is for creating a post request and correctly calculate the oAuth signature for LTI launches.
// It takes in a key value string pair and returns an Request object for you to work with.
func SignedFormRequest(url string, key string, secret string, params map[string]string) (*http.Request, error) {
	s := NewSigner("POST", url, key, secret, "", params)

	form, err := s.BuildAuthForm()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", url, strings.NewReader(form))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return request, nil
}

// NewSigner returns a Signer struct
func NewSigner(method string, url string, key string, secret string, body string, form map[string]string) Signer {
	return Signer{
		Method: method,
		URL:    url,
		Body:   body,
		Form:   form,
		Key:    key,
		Secret: secret,
	}
}

// Signer represents the data needed to create a valid OAuth signed request for LTI
type Signer struct {
	// The HTTP method to be used in the request and signing
	Method string

	// URL is used in the request object returned and also used to generate
	// a the base string for signature calculation.
	URL string

	// Key and Secret are both used to generate the OAuth signature / params
	Key    string
	Secret string

	// These both represent the different bodies of the LTI requets that need to be signed,
	// it's generally one or the other. E.g. Body when you need to send data in a callback to
	// an LTI consumer or Form when you want to sign an LTI form request to a provider.
	Body string
	Form map[string]string
}

// BuildAuthHeader generates an Authorization header to be used in requests, it's used when needing to
// send data back to an LTI consumer. It does this by generating the default OAuth params needed, hashing
// the body and signing the whole thing, this is then combined into an Authorization header string.
// For example: grade passback, this callback requires an XML body with the grade be passed back to the LTI
// consumer with a signed authorization header.
func (s Signer) BuildAuthHeader() (string, error) {
	params := make(map[string]string)
	s.addDefaultOAuthParams(params)

	params["oauth_body_hash"] = s.bodyHash()

	// generates signature based on params map and appends to the end of the map
	params["oauth_signature"] = s.signRequest(params)

	authHeader := `OAuth realm=""`

	for k, v := range params {
		authHeader += fmt.Sprintf(`,%s="%s"`, escape(k), escape(v))
	}

	log.WithFields(log.Fields{"Auth Header": authHeader}).Info("Authorization header created.")

	return authHeader, nil
}

// BuildAuthForm returns a formatted, OAuth signed string to be used in a x-www-form-urlencoded form request.
// Similar to what BuildAuthHeader is doing except this takes the parameters provided, appends the default OAuth ones
// on and signs the request.
func (s Signer) BuildAuthForm() (string, error) {
	if len(s.Form) < 1 {
		return "", errors.New("No form provided")
	}

	if err := s.addDefaultOAuthParams(s.Form); err != nil {
		return "", err
	}

	s.Form["oauth_signature"] = s.signRequest(s.Form)

	return s.escapeParams(s.Form), nil
}

// Adds the default oAuth params apart from oauth_body_hash and oauth_signature since these will be generated on the fly.
// This is simply a helper to append the commonly used OAuth params to the different type of requests.
func (s Signer) addDefaultOAuthParams(params map[string]string) error {
	n, err := util.RandomString(15)
	if err != nil {
		return err
	}

	params["oauth_version"] = "1.0"
	params["oauth_nonce"] = n
	params["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	params["oauth_consumer_key"] = s.Key
	params["oauth_signature_method"] = "HMAC-SHA1"

	return nil
}

// signRequest handles the creation of the base string and the signing of that base string
// to create the end oauth_signature parameter.
func (s Signer) signRequest(params map[string]string) string {

	baseString := s.createBaseString(params)

	// Ampersand appended due to oAuth 1.0 spec
	secret := s.Secret + "&"

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(baseString))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// createBaseString builds up a base string to be hashed and used as a signature.
func (s Signer) createBaseString(params map[string]string) string {
	baseString := s.Method + "&" + escape(s.URL) + "&"

	baseString = baseString + escape(s.escapeParams(params))

	log.WithFields(log.Fields{"Base String": baseString}).Info("Basestring for oAuth signature.")

	return baseString
}

// bodyHash takes a slice of bytes and hashes and base64 encodes that data.
func (s Signer) bodyHash() string {
	// Hash the body for the oauth_body_hash
	hasher := sha1.New()
	hasher.Write([]byte(s.Body))
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// Escapes params for a standard LTI launch, doesn't encode the equals
func (s Signer) escapeParams(params map[string]string) string {

	var paramString string

	keys := sortKeys(params)

	for i, key := range keys {
		if i > 0 {
			paramString += "&"
		}
		paramString += escape(key) + "=" + escape(params[key])
	}
	return paramString
}

// sortKeys iterates over the map passed in and returns a slice of string keys
// which are now alphabetically ordered.
func sortKeys(params map[string]string) []string {
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func escape(s string) string {
	t := make([]byte, 0, 3*len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEscapable(c) {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		} else {
			t = append(t, s[i])
		}
	}
	return string(t)
}

func isEscapable(b byte) bool {
	return !('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~')
}
