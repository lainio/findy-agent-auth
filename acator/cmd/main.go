package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"

	"github.com/findy-network/findy-agent-auth/acator/authn"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

func main() {
	os.Args = slices.Insert(os.Args, 1, "-logtostderr") // 1 -> first flag
	glog.CopyStandardLogTo("ERROR")                     // err2 -> glog.ErrorX
	defer err2.Catch(err2.Stderr)

	flag.Usage = usage
	flag.Parse()
	if flag.CommandLine.Arg(0) == "auth" {
		try.To(startServerCmd.Parse(flag.Args()[1:]))
	}

	jsonAPI := false
	if startServerCmd.Arg(0) == "-" {
		authnCmd = authnCmd.TryReadJSON(os.Stdin)
		jsonAPI = true
	} else if fname := startServerCmd.Arg(0); fname != "" {
		glog.V(2).Infoln("fname:", fname)
		f := try.To1(os.Open(fname))
		defer f.Close()
		authnCmd = authnCmd.TryReadJSON(f)
		jsonAPI = true
	}

	if dryRun {
		try.To(authnCmd.Validate())
		fmt.Println(string(try.To1(json.MarshalIndent(authnCmd, "", "\t"))))
		return
	}

	r := try.To1(authnCmd.Exec(os.Stdout))

	if jsonAPI {
		fmt.Println(r.String())
	} else {
		fmt.Println(r.Token)
	}
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: ")
	fmt.Fprintf(flag.CommandLine.Output(), "fido-call [-common-flags] auth [-cmd-flags]\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  auth cmd calls the server's WebAuthn API\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "common-flags:\n")
	flag.PrintDefaults()
}

var (
	dryRun         bool
	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)

	authnCmd = authn.Cmd{
		SubCmd:     "login",
		UserName:   "",
		CookiePath: "",
		URL:        "http://localhost:8090",

		LoginBegin: authn.Endpoint{
			Method:   "POST",
			Path:     "%s/assertion/options",
			Payload:  `{"username":"%s"}`,
			MiddlePL: `{"publicKey": %s}`,
		},

		LoginFinish: authn.Endpoint{
			Method:  "POST",
			Path:    "%s/assertion/result",
			Payload: ``,
		},

		RegisterBegin: authn.Endpoint{
			Method:   "POST",
			Path:     "%s/attestation/options",
			Payload:  `{"username":"%s"}`,
			MiddlePL: `{"publicKey": %s}`,
		},

		RegisterFinish: authn.Endpoint{
			Method:  "POST",
			Path:    "%s/attestation/result",
			Payload: ``,
		},

		AAGUID:  "12c85a48-4baf-47bd-b51f-f192871a1511",
		Key:     "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c",
		Counter: 0,
	}
)

func init() {
	startServerCmd.StringVar(&authnCmd.URL, "url", authnCmd.URL, "web authn server url")
	startServerCmd.StringVar(&authnCmd.CookieFile, "cookies", authnCmd.CookieFile,
		"cookies to store between calls")
	startServerCmd.StringVar(&authnCmd.CookiePath, "cookie-path", authnCmd.CookiePath,
		"path to page which loads needed cookies")

	startServerCmd.StringVar(&authnCmd.RegisterBegin.Path, "reg-begin",
		authnCmd.RegisterBegin.Path, "format string to build endpoint path")
	startServerCmd.StringVar(&authnCmd.RegisterFinish.Path, "reg-finish",
		authnCmd.RegisterFinish.Path, "format string to build endpoint path")
	startServerCmd.StringVar(&authnCmd.LoginBegin.Path, "log-begin",
		authnCmd.LoginBegin.Path, "format string to build endpoint path")
	startServerCmd.StringVar(&authnCmd.LoginFinish.Path, "log-finish",
		authnCmd.LoginFinish.Path, "format string to build endpoint path")

	startServerCmd.StringVar(&authnCmd.RegisterBegin.Method, "reg-begin-met",
		authnCmd.RegisterBegin.Method, "format string to build endpoint method")
	startServerCmd.StringVar(&authnCmd.RegisterFinish.Method, "reg-finish-met",
		authnCmd.RegisterFinish.Method, "format string to build endpoint method")
	startServerCmd.StringVar(&authnCmd.LoginBegin.Method, "log-begin-met",
		authnCmd.LoginBegin.Method, "format string to build endpoint method")
	startServerCmd.StringVar(&authnCmd.LoginFinish.Method, "log-finish-met",
		authnCmd.LoginFinish.Method, "format string to build endpoint method")

	startServerCmd.StringVar(&authnCmd.RegisterBegin.Payload, "reg-begin-pl",
		authnCmd.RegisterBegin.Payload, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.RegisterFinish.Payload, "reg-finish-pl",
		authnCmd.RegisterFinish.Payload, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.LoginBegin.Payload, "log-begin-pl",
		authnCmd.LoginBegin.Payload, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.RegisterBegin.InPL, "reg-begin-pl-in",
		authnCmd.RegisterBegin.InPL, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.LoginBegin.InPL, "log-begin-pl-in",
		authnCmd.LoginBegin.InPL, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.LoginBegin.MiddlePL, "log-begin-pl-middle",
		authnCmd.LoginBegin.MiddlePL, "format string to build endpoint payload JSON template to SEND")
	startServerCmd.StringVar(&authnCmd.RegisterBegin.MiddlePL, "reg-begin-pl-middle",
		authnCmd.RegisterBegin.MiddlePL, "format string to build endpoint payload JSON template to SEND")
	startServerCmd.StringVar(&authnCmd.LoginFinish.Payload, "log-finish-pl",
		authnCmd.LoginFinish.Payload, "format string to build endpoint payload JSON template")

	startServerCmd.StringVar(&authnCmd.SubCmd, "subcmd", authnCmd.SubCmd, "sub command: login|register")
	startServerCmd.StringVar(&authnCmd.UserName, "name", authnCmd.UserName, "user name")
	startServerCmd.StringVar(&authnCmd.AAGUID, "aaguid", authnCmd.AAGUID, "AAGUID")
	startServerCmd.StringVar(&authnCmd.Key, "key", authnCmd.Key, "authenticator master key")
	startServerCmd.StringVar(&authnCmd.Origin, "origin", authnCmd.Origin, "use if origin needs to be different than from -url")
	startServerCmd.Uint64Var(&authnCmd.Counter, "counter", authnCmd.Counter, "Authenticator's counter, used for cloning detection")

	startServerCmd.BoolVar(&dryRun, "dry-run", dryRun, "dry run, e.g. output current cmd as JSON")
}
