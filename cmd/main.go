package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/satori/go.uuid"

	"ghe.iparadigms.com/Integrations/Tool-Proxy-Registration.git/signer"
)

func ltiRequestExample() {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header)
	}))
	defer ts.Close()

	endpoint := "http://ip-cpod3-vm1.oak.iparadigms.com:9002/api/lti/1p0/assignment"

	resourceID := uuid.NewV4().String()
	formParams := map[string]string{
		"context_id":                       uuid.NewV4().String(),
		"context_label":                    uuid.NewV4().String(),
		"lis_person_contact_email_primary": "aprice@iparadigms.com",
		"lis_person_name_given":            uuid.NewV4().String(),
		"lis_person_name_family":           uuid.NewV4().String(),
		"lis_person_name_full":             uuid.NewV4().String(),
		"lti_message_type":                 "basic-lti-launch-request",
		"resource_link_id":                 resourceID,
		"resource_link_title":              "Assignment Title",
		"user_id":                          uuid.NewV4().String(),
		"roles":                            "Instructor",
		"lti_version":                      "LTI-1p0",
		"lang":                             "en",
		"oauth_nonce":                      uuid.NewV4().String(),
		"oauth_timestamp":                  strconv.Itoa(int(time.Now().Unix()))}

	// Sign the request and add the auth header
	request, err := signer.SignedFormRequest(endpoint, "61390", "testing1", formParams)
	if err != nil {
		fmt.Println("Error signing request: ", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(response)
}

func jsonBodySignerExample() {
	url := "https://example.com"
	key := "abc"
	secret := "secret"
	body := `{"outcomes_tool_placement_url":"https://api.turnitin.com/api/lti/1p0/outcome_tool_data/123456789?lang=en_us","paperid":"123456789","lis_result_sourcedid":"blah"}`

	request, _ := signer.SignedBodyRequest(url, key, secret, body)
	request.Header.Add("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(response)

	rebody, _ := ioutil.ReadAll(response.Body)
	fmt.Println("body:", string(rebody))
}

func main() {
	jsonBodySignerExample()
}
