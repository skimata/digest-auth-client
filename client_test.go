package digestauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var sampleChallegeData = `
realm="testrealm@host.com",
qop="auth,auth-int",
nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
opaque="5ccc069c403ebaf9f0171e9517f40e41"
`

func TestDigestAuthConn(t *testing.T) {
	challengeVal := fmt.Sprintf("%s %s", digestPrefix, sampleChallegeData)
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(authHeader) == "" {
				w.Header().Add(authChallengeHeader, challengeVal)
				w.WriteHeader(http.StatusUnauthorized)
			}
		}),
	)
	defer ts.Close()

	c := Client{
		username: "foo",
		password: "bar",

		httpCaller: ts.Client(), // http.DefaultClient,
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Error(err)
	}

	resp, err := c.AuthedDo(req)
	if err != nil {
		t.Error(err)
	}
	t.Logf("resp %#v\n", resp)
}
