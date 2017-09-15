package digestauth

import (
	"crypto/md5"
	"crypto/rand"
	"regexp"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// https://tools.ietf.org/html/rfc2617

const (
	authChallengeHeader = "WWW-Authenticate"
	authHeader          = "Authorization"
	digestPrefix        = "Digest"
)

type nonceCounter uint32

var maxNonceCounter nonceCounter

func init() {
	maxVal, _ := strconv.ParseInt("ffffffff", 16, 64)
	maxNonceCounter = nonceCounter(maxVal)
}

type httpCaller interface {
	// Get(url string) (resp *http.Response, err error)
	Do(req *http.Request) (resp *http.Response, err error)
}

type DigestAuthClient struct {
	httpCaller
	*digestChallenge
	username, password string

	Cnonce string
	NC     nonceCounter
	QOP    string
}

func (dac *DigestAuthClient) Conn(uri string) error {
	var err error

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return err
	}

	resp, err := dac.Do(req)
	if err != nil {
		return err
	}

	// expect HTTP/1.1 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("expected %s to respond with status code %v, but got %v", uri, http.StatusUnauthorized, resp.StatusCode)
	}

	// read 'WWW-Authenticate' val from header
	hdrVal := resp.Header.Get(authChallengeHeader)
	if hdrVal == "" {
		return fmt.Errorf("expected response to have a header with %s", authChallengeHeader)
	}

	// read challenge info
	dac.digestChallenge, err = readChallenge(hdrVal)
	if err != nil {
		return fmt.Errorf("there was a problem reading the digest challenge: %s", err.Error())
	}
	fmt.Printf("challengeVal: %#v\n", dac.digestChallenge)

	// generate a client nonce
	dac.Cnonce, err = generateNonce()
	if err != nil {
		return err
	}

	// choose QOP response from options
	dac.QOP = dac.determineQOP()

	req, err = http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return err
	}

	// challengeResp := dac.response(req.Method, req.URL.RequestURI(), req.Body)
	// fmt.Printf("challengeResp: %#v\n", challengeResp)

	dac.ApplyAuth(req)

	return nil
}

func (dac DigestAuthClient) determineQOP() string {
	qopSupportsAuth := sliceContainsString(dac.QOPOptions, "auth")
	qopSupportsAuthInt := sliceContainsString(dac.QOPOptions, "auth-int")

	if qopSupportsAuth {
		return "auth"
	}
	if qopSupportsAuthInt {
		return "auth-in"
	}
	return ""
}

func readChallenge(s string) (*digestChallenge, error) {
	if !strings.HasPrefix(s, digestPrefix) {
		return nil, fmt.Errorf("expected header value to begin with: %s", digestPrefix)
	}
	s = strings.TrimPrefix(s, digestPrefix)

	m := map[string]interface{}{}
	re := regexp.MustCompile(`\w+\="([^"])*"`)
	for _, pair := range re.FindAllString(s, -1) {
		kv := strings.SplitN(pair, "=", 2)
		val, err := cleanValue(kv[1])
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

func cleanValue(s string) (interface{}, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		var err error
		if s, err = strconv.Unquote(s); err != nil {
			return nil, err
		}
	}

	if !strings.Contains(s, ",") {
		return s, nil
	}

	resp := []string{}
	for _, v := range strings.Split(s, ",") {
		resp = append(resp, strings.TrimSpace(v))
	}
	return resp, nil
}

// 3.2.1 The WWW-Authenticate Response Header
type digestChallenge struct {
	Realm, Domain, Nonce, Opaque, Stale, Algorithm string
	QOPOptions                                     []string `json:"qop"`
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

func (dac *DigestAuthClient) ApplyAuth(req *http.Request) {
	hdrVal := dac.response(req.Method, req.URL.RequestURI(), req.Body).printHeaderVal()

	if dac.Opaque != "" {
		hdrVal = fmt.Sprintf(`%s, opaque="%s"`, hdrVal, dac.Opaque)
	}
	fmt.Println("hdrVal", hdrVal)
	req.Header.Set(authHeader, hdrVal)
}

func (dr *digestResponse) printHeaderVal() string {
	hdrVal := fmt.Sprintf(
		`%s username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s`,
		digestPrefix, dr.Username, dr.Realm, dr.Nonce, dr.URI, dr.Response, dr.Algorithm,
	)

	if dr.QOP != "" {
		hdrVal = fmt.Sprintf("%s, %s", hdrVal, fmt.Sprintf(
			`cnonce="%s", nc=%s, qop=%s`,
			dr.Cnonce, dr.NC, dr.QOP,
		))
	}
	return hdrVal
}

func (dac *DigestAuthClient) response(reqMethod, reqPath string, reqBody io.ReadCloser) *digestResponse {
	// If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
	// response=MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
	// If the qop directive is unspecified, then compute the response as follows:
	// response=MD5(HA1:nonce:HA2)

	dac.incrCounter()
	resp := &digestResponse{
		Username:  dac.username,
		Realm:     dac.Realm,
		Nonce:     dac.Nonce,
		URI:       reqPath,
		Algorithm: dac.Algorithm,
		Opaque:    dac.Opaque,
	}

	ha1 := dac.ha1()
	ha2 := dac.ha2(reqMethod, reqPath, reqBody)
	hash := md5.New()
	if dac.QOP != "" {
		io.WriteString(hash, fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, dac.Nonce, dac.NC.printHex(), dac.Cnonce, dac.QOP, ha2))
		resp.Cnonce = dac.Cnonce
		resp.QOP = dac.QOP
		resp.NC = dac.NC.printHex()
	}
	io.WriteString(hash, fmt.Sprintf("%s:%s:%s", ha1, dac.Nonce, ha2))

	resp.Response = fmt.Sprintf("%x", hash.Sum(nil))

	return resp
}

func (dac *DigestAuthClient) ha1() string {
	// If the algorithm directive's value is "MD5" or unspecified, then HA1 is
	// HA1=MD5(username:realm:password)

	// If the algorithm directive's value is "MD5-sess", then HA1 is
	// HA1=MD5(MD5(username:realm:password):nonce:cnonce)
	hash := md5.New()
	io.WriteString(hash, fmt.Sprintf("%s:%s:%s", dac.username, dac.Realm, dac.password))
	ha1 := fmt.Sprintf("%x", hash.Sum(nil))

	if dac.Algorithm != "MD5-sess" {
		return ha1
	}

	outerHash := md5.New()
	io.WriteString(outerHash, fmt.Sprintf("%s:%s:%s", ha1, dac.Nonce, dac.Cnonce))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (dac *DigestAuthClient) ha2(reqMethod, reqPath string, reqBody io.ReadCloser) string {
	// 	If the qop directive's value is "auth" or is unspecified, then HA2 is
	// 	HA2=MD5(method:digestURI)

	// 	If the qop directive's value is "auth-int", then HA2 is
	// 	HA2=MD5(method:digestURI:MD5(entityBody))

	hash := md5.New()
	if dac.QOP != "auth-int" {
		io.WriteString(hash, fmt.Sprintf("%s:%s", reqMethod, reqPath))
	} else {
		hashEntityBody := md5.New()
		io.Copy(hashEntityBody, reqBody)
		entityBody := fmt.Sprintf("%x", hashEntityBody.Sum(nil))
		io.WriteString(hash, fmt.Sprintf("%s:%s:%s", reqMethod, reqPath, entityBody))
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func generateNonce() (string, error) {
	c := 10
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	hash := md5.New()
	io.WriteString(hash, string(b))
	return strings.TrimSpace(fmt.Sprintf("%x\n", hash.Sum(nil))), nil
}

func (dac *DigestAuthClient) incrCounter() (string, error) {
	if dac.NC > maxNonceCounter {
		return "", fmt.Errorf("nonce counter is too large: %v", dac.NC)

	}
	dac.NC++
	return dac.NC.printHex(), nil
}

func (nc nonceCounter) printHex() string {
	return fmt.Sprintf("%08x", nc)
}

func sliceContainsString(slice []string, s string) bool {
	for _, v := range slice {
		if s == v {
			return true
		}
	}
	return false
}
