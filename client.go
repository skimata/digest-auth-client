package digestauth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	authChallengeHeader = "WWW-Authenticate"
	authHeader          = "Authorization"
	digestPrefix        = "Digest"
	qopAuth             = "auth"
	qopAuthInt          = "auth-int"
)

type nonceCounter uint32

var (
	maxNonceCounter           nonceCounter
	regexDigestChallengeParam = regexp.MustCompile(`\w+\="([^"])*"`)
)

func init() {
	maxVal, _ := strconv.ParseInt("ffffffff", 16, 64)
	maxNonceCounter = nonceCounter(maxVal)
}

type httpCaller interface {
	Do(*http.Request) (*http.Response, error)
}

// Client holds the details need to respond to digest auth challenge and generate a auth request
type Client struct {
	httpCaller
	*digestChallenge
	username, password string
	nc                 nonceCounter
	qop                string
}

// https://tools.ietf.org/html/rfc2617
// 3.2.1 The WWW-Authenticate Response Header
type digestChallenge struct {
	Realm, Domain, Nonce, Opaque, Stale, Algorithm string
	QOPOptions                                     []string `json:"qop"`
}

// https://tools.ietf.org/html/rfc2617
// 3.2.2 The Authorization Request Header
type digestResponse struct {
	Username, Realm, Nonce, URI, Response, Algorithm, Cnonce, Opaque, QOP, NC string
}

// NewClient initializes a new client with http.DefaultClient and username/password
func NewClient(username, password string) *Client {
	return &Client{
		httpCaller: http.DefaultClient,
		username:   username,
		password:   password,
	}
}

// WithHTTPClient is used to optional set the client with a different httpCaller
func (c *Client) WithHTTPClient(hc httpCaller) *Client {
	c.httpCaller = hc
	return c
}

// ApplyAuth will set an authorization header to the request.
func (c *Client) ApplyAuth(req *http.Request) error {
	var err error

	// first request off the client may need to initiate and process the challenge
	if c.digestChallenge == nil {
		if err = c.getDigestChallenge(req); err != nil {
			return err
		}
	}

	// generate a response
	dr, err := c.response(req.Method, req.URL.RequestURI(), req.Body)
	if err != nil {
		return err
	}

	// generate the header
	hdrVal := dr.printHeaderVal()
	if c.Opaque != "" {
		hdrVal = fmt.Sprintf(`%s, opaque="%s"`, hdrVal, c.Opaque)
	}

	// apply the header
	req.Header.Set(authHeader, hdrVal)

	return nil
}

// AuthedDo will set an authorization header to the request, and call it with the Client httpCaller
func (c *Client) AuthedDo(req *http.Request) (*http.Response, error) {
	// apply auth to request header
	if err := c.ApplyAuth(req); err != nil {
		return nil, err
	}

	// make request
	return c.Do(req)
}

func (c *Client) getDigestChallenge(req *http.Request) error {
	// make request to get a challenge response
	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	// expect HTTP/1.1 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("expected %s to respond with status code %v, but got %v", req.URL.Host, http.StatusUnauthorized, resp.StatusCode)
	}

	// read 'WWW-Authenticate' val from header
	hdrVal := resp.Header.Get(authChallengeHeader)
	if hdrVal == "" {
		return fmt.Errorf("expected response to have a header with %s", authChallengeHeader)
	}

	// read challenge info
	c.digestChallenge, err = readChallenge(hdrVal)
	if err != nil {
		return fmt.Errorf("there was a problem reading the digest challenge: %s", err.Error())
	}

	// choose QOP response from options
	c.qop = c.determineQOP()
	return nil
}

// will choose "auth" > "auth-in"
func (c *Client) determineQOP() string {
	qopSupportsAuth := sliceContainsString(c.QOPOptions, qopAuth)
	qopSupportsAuthInt := sliceContainsString(c.QOPOptions, qopAuthInt)

	if qopSupportsAuth {
		return qopAuth
	}
	if qopSupportsAuthInt {
		return qopAuthInt
	}
	return ""
}

func readChallenge(s string) (*digestChallenge, error) {
	if !strings.HasPrefix(s, digestPrefix) {
		return nil, fmt.Errorf("expected header value to begin with: %s", digestPrefix)
	}
	s = strings.TrimPrefix(s, digestPrefix)

	m := map[string]interface{}{}
	for _, pair := range regexDigestChallengeParam.FindAllString(s, -1) {
		kv := strings.SplitN(pair, "=", 2)
		val, err := cleanUpValue(kv[1])
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

func cleanUpValue(s string) (interface{}, error) {
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

// initialize w/ defaults
func newDigestChallenge() *digestChallenge {
	return &digestChallenge{
		Algorithm: "MD5",
	}
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

func (c *Client) response(reqMethod, reqPath string, reqBody io.ReadCloser) (*digestResponse, error) {
	// If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
	// response=MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
	// If the qop directive is unspecified, then compute the response as follows:
	// response=MD5(HA1:nonce:HA2)

	// generate a client nonce
	cnonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	nc, err := c.incrNC()
	if err != nil {
		return nil, err
	}

	resp := &digestResponse{
		Username:  c.username,
		Realm:     c.Realm,
		Nonce:     c.Nonce,
		URI:       reqPath,
		Algorithm: c.Algorithm,
		Opaque:    c.Opaque,
	}

	ha1 := c.ha1(cnonce)
	ha2 := c.ha2(reqMethod, reqPath, reqBody)
	if c.qop != "" {
		resp.Response = toMD5(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, c.Nonce, nc, cnonce, c.qop, ha2))
		resp.Cnonce = cnonce
		resp.QOP = c.qop
		resp.NC = nc
	}
	resp.Response = toMD5(fmt.Sprintf("%s:%s:%s", ha1, c.Nonce, ha2))

	return resp, nil
}

func (c *Client) ha1(cnonce string) string {
	ha1 := toMD5(fmt.Sprintf("%s:%s:%s", c.username, c.Realm, c.password))
	// If the algorithm directive's value is "MD5" or unspecified, then HA1 is
	// HA1=MD5(username:realm:password)
	if c.Algorithm != "MD5-sess" {
		return ha1
	}
	// If the algorithm directive's value is "MD5-sess", then HA1 is
	// HA1=MD5(MD5(username:realm:password):nonce:cnonce)
	return toMD5(fmt.Sprintf("%s:%s:%s", ha1, c.Nonce, cnonce))
}

func (c *Client) ha2(reqMethod, reqPath string, reqBody io.ReadCloser) string {
	// 	If the qop directive's value is "auth-int", then HA2 is
	// 	HA2=MD5(method:digestURI:MD5(entityBody))
	if c.qop == qopAuthInt {
		hashEntityBody := md5.New()
		io.Copy(hashEntityBody, reqBody)
		return toMD5(fmt.Sprintf("%s:%s:%s", reqMethod, reqPath, hashToString(hashEntityBody)))
	}

	// 	If the qop directive's value is "auth" or is unspecified, then HA2 is
	// 	HA2=MD5(method:digestURI)
	return toMD5(fmt.Sprintf("%s:%s", reqMethod, reqPath))
}

func generateNonce() (string, error) {
	c := 10
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return toMD5(string(b)), nil
}

func (c *Client) incrNC() (string, error) {
	if c.nc > maxNonceCounter {
		return "", fmt.Errorf("nonce counter is too large: %v", c.nc)

	}
	c.nc++
	return c.nc.printHex(), nil
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

func toMD5(s string) string {
	hash := md5.New()
	io.WriteString(hash, s)
	return hashToString(hash)
}

func hashToString(h hash.Hash) string {
	return fmt.Sprintf("%x", h.Sum(nil))
}
