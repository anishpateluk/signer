package signer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var body = `{"outcomes_tool_placement_url":"https://api.turnitin.com/api/lti/1p0/outcome_tool_data/123456789?lang=en_us","paperid":"123456789","lis_result_sourcedid":"fyhsjdg7fhje89bklew8"}`

var formParams = map[string]string{
	"context_id":                       "12345",
	"context_label":                    "12345",
	"lis_person_contact_email_primary": "test@iparadigms.com",
	"lis_person_name_given":            "Unit",
	"lis_person_name_family":           "Test",
	"lis_person_name_full":             "Unit Test",
	"lti_message_type":                 "basic-lti-launch-request",
	"resource_link_id":                 "12345",
	"resource_link_title":              "Assignment Title",
	"user_id":                          "12346",
	"roles":                            "Instructor",
	"lti_version":                      "LTI-1p0",
	"lang":                             "en",
	"oauth_nonce":                      "nonce",
	"oauth_timestamp":                  "timestamp",
}

func TestSignedBodyRequest(t *testing.T) {
	req, _ := SignedBodyRequest("http://example.com", "1234", "abcd", body)

	if req.Header.Get("Authorization") == "" {
		t.Errorf(`Authorization head does not exist.`)
	}
}

func TestBuildAuthHeader(t *testing.T) {
	s := NewSigner("http://example.com", "1234", "abcd", "test body", nil)
	s.BuildAuthHeader()

	h, _ := s.BuildAuthHeader()
	if !strings.Contains(h, `OAuth realm=""`) {
		t.Errorf(`BuildAuthHeader returned %s, expected: 'OAuth realm=""'`, h)
	}
}

func TestBodyHash(t *testing.T) {
	hash := "8zvVCDnUBUsiOMVnRz9Ahc8bPWU="
	s := NewSigner("http://example.com", "1234", "abcd", body, nil)
	genhash := s.bodyHash()

	if genhash != hash {
		t.Errorf(`Hash not equal to %s. Got %s instead`, hash, genhash)
	}
}

func TestIsEscapable(t *testing.T) {
	var byteTests = []struct {
		in  byte
		out bool
	}{
		{'@', true},
		{'&', true},
		{'A', false},
		{'b', false},
	}

	for _, tt := range byteTests {
		if isEscapable(tt.in) != tt.out {
			t.Error("Wrong boolean value returned")
		}
	}
}

func TestEscape(t *testing.T) {
	var strings = []struct {
		in  string
		out string
	}{
		{"abcd1234$£@!&", "abcd1234%24%C2%A3%40%21%26"},
		{"&", "%26"},
		{" ", "%20"},
		{"@", "%40"},
		{"abcd1234", "abcd1234"},
	}

	for _, tt := range strings {
		if escape(tt.in) != tt.out {
			t.Errorf("String incorrectly escaped expedcted: %s; got: %s", tt.out, escape(tt.in))
		}
	}
}

func TestSortKeys(t *testing.T) {
	sorted := []string{
		"oauth_body_hash",
		"oauth_consumer_key",
		"oauth_nonce",
		"oauth_signature_method",
		"oauth_timestamp",
		"oauth_version",
	}

	params := map[string]string{
		"oauth_version":          "1.0",
		"oauth_nonce":            "random",
		"oauth_timestamp":        "timestamp",
		"oauth_consumer_key":     "abc123",
		"oauth_body_hash":        "bodyhash",
		"oauth_signature_method": "HMAC-SHA1",
	}

	keys := sortKeys(params)

	for k, v := range keys {
		if v != sorted[k] {
			t.Errorf(`Sorted key: %s doesn't match presorted key: %s`, v, sorted[k])
			break
		}
	}
}

func TestCreateBaseString(t *testing.T) {
	gen := `POST&http%3A%2F%2Fexample.com&oauth_body_hash%3Dbodyhash%26oauth_consumer_key%3Dabc123%26oauth_nonce%3Drandom%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3Dtimestamp%26oauth_version%3D1.0`
	params := map[string]string{
		"oauth_version":          "1.0",
		"oauth_nonce":            "random",
		"oauth_timestamp":        "timestamp",
		"oauth_consumer_key":     "abc123",
		"oauth_body_hash":        "bodyhash",
		"oauth_signature_method": "HMAC-SHA1",
	}

	s := Signer{URL: "http://example.com"}

	baseString := s.createBaseString(params)

	if baseString != gen {
		t.Errorf(`Incorrect base string generated. Expected: %s. Got: %s`, gen, baseString)
	}
}

func TestSignRequest(t *testing.T) {
	gen := `6Te1LTOGEnM6qUYIpinnoVO4jms=`
	params := map[string]string{
		"oauth_version":          "1.0",
		"oauth_nonce":            "random",
		"oauth_timestamp":        "timestamp",
		"oauth_consumer_key":     "abc123",
		"oauth_body_hash":        "bodyhash",
		"oauth_signature_method": "HMAC-SHA1",
	}

	s := Signer{
		URL:    "http://example.com",
		Secret: "secret",
	}

	sig := s.signRequest(params)

	if sig != gen {
		t.Errorf(`Signature: %s does not match %s`, sig, gen)
	}

}

func TestLTISign(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header)
	}))
	defer ts.Close()

	request, err := SignedFormRequest(ts.URL, "1000", "qwerty", formParams)
	if err != nil {
		t.Errorf(`Request failed to return: Request: %s Error: %s`, request, err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	response, err := client.Do(request)
	if err != nil {
		t.Errorf(`Request failed to send: %s`, err)
	}
	if response.StatusCode != 200 {
		t.Errorf(`Response did not have a 200 status code`)
	}
}

func TestBuildAuthForm(t *testing.T) {
	form := make(map[string]string)
	_, err := SignedFormRequest("http://example.com", "1234", "secret", form)
	if err == nil {
		t.Error(`Error should be returned. Empty form passed in.`)
	}
}

func TestValidateSignature(t *testing.T) {
	u := "http://example.com"
	secret := "secret"

	params := map[string]string{
		"oauth_version":          "1.0",
		"oauth_nonce":            "random",
		"oauth_timestamp":        "timestamp",
		"oauth_consumer_key":     "abc123",
		"oauth_body_hash":        "bodyhash",
		"oauth_signature_method": "HMAC-SHA1",
	}

	// Generate a signaute from params above
	s := Signer{
		URL:    u,
		Secret: secret,
	}
	params["oauth_signature"] = s.signRequest(params)

	form := url.Values{}

	for k, v := range params {
		form.Add(k, v)
	}

	// Validate that the signature is true
	b := ValidateSignature(u, form, secret)
	if b == false {
		t.Errorf(`ValidateSignature could not verify the signaute.`)
	}

	// Now prove that an incorrect signature returns false
	b = ValidateSignature(u, form, "wrongSecret")
	if b == true {
		t.Errorf(`ValidateSignature incorrectly verified the signaute.`)
	}
}
