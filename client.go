package digestauthclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	authChallengeHeader = "WWW-Authenticate"
)

type DigestAuthClient struct {
	Username, Password, URI string
}

func (da *DigestAuthClient) Conn() error {
	resp, err := http.Get(da.URI)
	if err != nil {
		return err
	}

	// expect HTTP/1.1 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("expected %s to respond with status code %v, but got %v", da.URI, http.StatusUnauthorized, resp.StatusCode)
	}

	// read 'WWW-Authenticate' val from header
	hdrVal := resp.Header.Get(authChallengeHeader)
	if hdrVal == "" {
		return fmt.Errorf("expected response to have a header with %s", authChallengeHeader)
	}

	// rea
	challengeVal, err := readChallenge(hdrVal)
	if err != nil {
		return fmt.Errorf("there was a problem reading the digest challenge: %s", err.Error())
	}

	fmt.Printf("challengeVal: %#v\n", challengeVal)

	return nil
}

func readChallenge(s string) (*digestChallenge, error) {
	const digestPrefix = "Digest"

	if !strings.HasPrefix(s, digestPrefix) {
		return nil, fmt.Errorf("expected header value to begin with: %s", digestPrefix)
	}
	s = strings.TrimPrefix(s, digestPrefix)

	m := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(pair, "=", 2)
		val, err := cleanString(kv[1])
		if err != nil {
			return nil, fmt.Errorf("problem parsing header; %s", err.Error())
		}
		m[strings.TrimSpace(kv[0])] = val
	}

	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	resp := newDigestChallenge()
	if err := json.Unmarshal(b, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func cleanString(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		return strconv.Unquote(s)
	}
	return s, nil
}

// 3.2.1 The WWW-Authenticate Response Header
type digestChallenge struct {
	Realm, Domain, Nonce, Opaque, Stale, Algorithm, QOP string
}

// initialize w/ defaults
func newDigestChallenge() *digestChallenge {
	return &digestChallenge{
		Algorithm: "MD5",
	}
}

// 3.2.2 The Authorization Request Header
type digestResponse struct {
	Username, Realm, Nonce, URI, Response, Algorithm, Cnonce, Opaque, QOP, NC string
}
