package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/mtsaas/tunneler/internal/api"
)

// outputJSON is set by --output json. Every command then writes its result
// to stdout as JSON, reports errors on stderr as JSON, and never prompts.
var outputJSON bool

// interactive reports whether a person is at a terminal to answer
// questions: never with --output json, nor when stdin or stderr is
// redirected. A character device is not enough of a test: /dev/null, the
// usual stdin of scripts, is one. It is a variable so that tests can be one.
var interactive = func() bool {
	return !outputJSON && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// result writes the outcome of a command: v as JSON, or text for a person.
// Text is printed as given, with no timestamp; timestamps belong to the
// timeline of a long-running command, which goes through log.
func result(v any, text string) {
	if outputJSON {
		json.NewEncoder(os.Stdout).Encode(v)
		return
	}
	fmt.Println(text)
}

// Exit statuses, so that a script or an agent can tell failures apart
// without reading messages. They are part of the CLI's contract.
const (
	exitFailure     = 1 // anything not listed below
	exitUsage       = 2 // bad flags or arguments
	exitNotLoggedIn = 3 // no login, or it expired and cannot be renewed: run "tunneler auth login"
	exitDenied      = 4 // no service you may reach matches, or the session is not yours
	exitAmbiguous   = 5 // the selector matches several services; the error lists them
	exitUnavailable = 6 // the service or the coordinator cannot be reached right now
)

// usageError marks a mistake in how the command was invoked.
type usageError struct{ error }

// errNotLoggedIn marks errors that "tunneler auth login" resolves.
var errNotLoggedIn = errors.New("not logged in")

// classify returns the stable code and exit status for an error.
func classify(err error) (code string, status int) {
	var apiErr *api.Error
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit): // a command run by "connect --" reports for itself
		return "command_failed", exit.ExitCode()
	case errors.As(err, new(usageError)):
		return "usage", exitUsage
	case errors.Is(err, errNotLoggedIn):
		return "not_logged_in", exitNotLoggedIn
	case errors.As(err, &apiErr):
		switch apiErr.Status {
		case http.StatusUnauthorized:
			return "not_logged_in", exitNotLoggedIn
		case http.StatusForbidden, http.StatusNotFound:
			return "access_denied", exitDenied
		case http.StatusConflict:
			return "ambiguous_selector", exitAmbiguous
		case http.StatusServiceUnavailable, http.StatusBadGateway:
			return "service_unavailable", exitUnavailable
		}
	}
	return "error", exitFailure
}

// fail reports err and returns the status to exit with.
func fail(w io.Writer, err error) int {
	code, status := classify(err)
	if code == "command_failed" {
		return status // it has already said why
	}
	if outputJSON {
		out := struct {
			Error   string        `json:"error"`
			Code    string        `json:"code"`
			Matches []api.Cluster `json:"matches,omitempty"`
		}{Error: err.Error(), Code: code}
		if apiErr := (*api.Error)(nil); errors.As(err, &apiErr) {
			out.Matches = apiErr.Matches
		}
		json.NewEncoder(w).Encode(out)
		return status
	}
	fmt.Fprintln(w, "tunneler:", err)
	return status
}

// usage makes a command's argument check fail with exitUsage.
func usage(check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := check(cmd, args); err != nil {
			return usageError{err}
		}
		return nil
	}
}
