/*
Package signer provides a way to generate presigned requests for LTI launches.

Signed body request, e.g. when sending data back to an LTI consumer, such as grade passback:

    req, err := signer.SignedBodyRequest("http://example.com", "key", "secret", "json body")

Signed x-www-form-urlencoded form request, e.g. when sending an LTI request to provider (LMS -> Turnitin)

    req, err := signer.SignedFormRequest("http://example.com", "key", "secret", paramsMap)

Alternatively you can generate the signed data without the request, like so:
    s := signer.NewSigner("http://google.com", "1234", "pass", "{lol: lol}", nil)

    n, err := s.BuildAuthHeader()

    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println(n)
*/
package signer
