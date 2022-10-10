// Package authn implements WebAuthn Cmd to Register and Login.
package authn

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"github.com/findy-network/findy-agent-auth/acator"
	"github.com/findy-network/findy-agent-auth/acator/cose"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"

	"github.com/lainio/err2/assert"
	"golang.org/x/net/publicsuffix"
)

type Cmd struct {
	SubCmd        string `json:"sub_cmd"`
	UserName      string `json:"user_name"`
	PublicDIDSeed string `json:"public_did_seed"`
	Url           string `json:"url,omitempty"`
	AAGUID        string `json:"aaguid,omitempty"`
	Key           string `json:"key,omitempty"`
	Counter       uint64 `json:"counter,omitempty"`
	Token         string `json:"token,omitempty"`
	Origin        string `json:"origin,omitempty"`
}

func (ac *Cmd) Validate() (err error) {
	defer err2.Return(&err)

	assert.P.NotEmpty(ac.SubCmd, "sub command needed")
	assert.P.Truef(ac.SubCmd == "register" || ac.SubCmd == "login",
		"wrong sub command: %s: want: register|login", ac.SubCmd)
	assert.P.NotEmpty(ac.UserName, "user name needed")
	assert.P.NotEmpty(ac.Url, "connection url cannot be empty")
	assert.P.NotEmpty(ac.AAGUID, "authenticator ID needed")
	assert.P.NotEmpty(ac.Key, "master key needed")

	return nil
}

type Result struct {
	SubCmd string `json:"sub_cmd,omitempty"`
	Token  string `json:"token"`
}

func (r Result) String() string {
	d, _ := json.Marshal(r)
	return string(d)
}

func (ac *Cmd) Exec(_ io.Writer) (r Result, err error) {
	defer err2.Returnf(&err, "execute authenticator")

	try.To(ac.Validate())

	try.To(cose.SetMasterKey(ac.Key))
	cmd := cmdModes[ac.SubCmd]
	acator.AAGUID = uuid.Must(uuid.Parse(ac.AAGUID))
	acator.Counter = uint32(ac.Counter)
	name = ac.UserName
	seed = ac.PublicDIDSeed
	urlStr = ac.Url
	if ac.Origin != "" {
		origin = ac.Origin
		originURL := try.To1(url.Parse(ac.Origin))
		acator.Origin = *originURL
	} else {
		origin = ac.Url
		originURL := try.To1(url.Parse(urlStr))
		acator.Origin = *originURL
	}
	jwtToken = ac.Token

	return *try.To1(execute[cmd]()), nil
}

func (ac Cmd) TryReadJSON(r io.Reader) Cmd {
	var newCmd Cmd
	try.To(json.NewDecoder(r).Decode(&newCmd))
	if newCmd.AAGUID == "" {
		newCmd.AAGUID = ac.AAGUID
	}
	if newCmd.Url == "" {
		newCmd.Url = ac.Url
	}
	if newCmd.Key == "" {
		newCmd.Key = ac.Key
	}
	if newCmd.Counter == 0 {
		newCmd.Counter = ac.Counter
	}
	return newCmd
}

type cmdMode int

const (
	register cmdMode = iota + 1
	login
)

type cmdFunc func() (*Result, error)

var (
	name     string
	seed     string
	urlStr   string
	origin   string
	jwtToken string

	c = setupClient()

	cmdModes = map[string]cmdMode{
		"register": register,
		"login":    login,
	}

	execute = []cmdFunc{
		empty,
		registerUser,
		loginUser,
	}
)

func empty() (*Result, error) {
	msg := "empty command handler called"
	glog.Warningln(msg)
	return nil, errors.New(msg)
}

func registerUser() (result *Result, err error) {
	defer err2.Returnf(&err, "register user")

	r := tryHTTPRequest("GET", urlStr+"/register/begin/"+name+"?seed="+seed, nil)
	defer r.Close()

	js := try.To1(acator.Register(r))

	r2 := tryHTTPRequest("POST", urlStr+"/register/finish/"+name, js)
	defer r2.Close()

	b := try.To1(io.ReadAll(r2))
	return &Result{SubCmd: "register", Token: string(b)}, nil
}

func loginUser() (_ *Result, err error) {
	defer err2.Returnf(&err, "login user")

	r := tryHTTPRequest("GET", urlStr+"/login/begin/"+name, nil)
	defer r.Close()

	js := try.To1(acator.Login(r))

	r2 := tryHTTPRequest("POST", urlStr+"/login/finish/"+name, js)
	defer r2.Close()

	var result Result
	try.To(json.NewDecoder(r2).Decode(&result))

	result.SubCmd = "login"
	return &result, nil
}

func tryHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser) {
	URL := try.To1(url.Parse(addr))
	request, _ := http.NewRequest(method, URL.String(), msg)

	echoReqToStdout(request)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Add("Accept", "*/*")
	// if we want to register a new authenticator, we must send valid JWT
	if jwtToken != "" {
		request.Header.Add("Authorization", "Bearer "+jwtToken)
	}

	response := try.To1(c.Do(request))

	c.Jar.SetCookies(URL, response.Cookies())

	if response.StatusCode != http.StatusOK {
		try.To(fmt.Errorf("status code: %v", response.Status))
	}
	echoRespToStdout(response)
	return response.Body
}

func setupClient() (client *http.Client) {
	options := cookiejar.Options{
		// All users of cookiejar should import "golang.org/x/net/publicsuffix"
		PublicSuffixList: publicsuffix.List,
	}

	jar := try.To1(cookiejar.New(&options))

	// allow self generated TLS certificate TODO check this later
	tx := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{
		Jar:       jar,
		Timeout:   time.Minute * 10,
		Transport: tx,
	}
	return
}

func echoReqToStdout(r *http.Request) {
	if glog.V(5) && r.Body != nil {
		r.Body = &struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, os.Stdout), r.Body}
	}
}

func echoRespToStdout(r *http.Response) {
	if glog.V(5) && r.Body != nil {
		r.Body = &struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, os.Stdout), r.Body}
	}
}
