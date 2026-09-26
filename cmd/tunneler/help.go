package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// Command groups, in the order the root help lists them.
const (
	groupCore   = "core"
	groupServer = "server"
)

// Annotations that add a section to a command's help.
const (
	helpArguments = "help:arguments" // what the positional arguments accept
	helpJSON      = "help:json"      // the shape of --output json
)

// help prints a command's help in the manner of the gh CLI: a sentence, then
// short uppercase sections of terse entries. Reference material lives in
// help topics rather than in any command's help.
func help(cmd *cobra.Command, _ []string) {
	w := cmd.OutOrStdout()
	headline := strings.TrimSpace(cmpOr(cmd.Long, cmd.Short))
	if cmd.Long == "" && !strings.HasSuffix(headline, ".") {
		headline += "."
	}
	fmt.Fprintln(w, headline)
	if cmd.IsAdditionalHelpTopicCommand() {
		return // a topic is its text
	}
	// --help is listed once, at the root, as gh does.
	cmd.InitDefaultHelpFlag()
	if f := cmd.Flags().Lookup("help"); f != nil {
		f.Usage, f.Hidden = "Show help for a command", cmd.HasParent()
	}

	usage := cmd.UseLine()
	if cmd.HasAvailableSubCommands() {
		usage = cmd.CommandPath() + " <command> [flags]"
	}
	section(w, "USAGE", "  "+usage)

	// Subcommands by group; those without a group are "additional", and
	// those that only carry text are help topics.
	groups := map[string][]*cobra.Command{}
	for _, sub := range cmd.Commands() {
		switch {
		case sub.Hidden || sub.Name() == "help":
		case sub.IsAdditionalHelpTopicCommand():
			groups["topics"] = append(groups["topics"], sub)
		default:
			groups[sub.GroupID] = append(groups[sub.GroupID], sub)
		}
	}
	for _, g := range cmd.Groups() {
		section(w, g.Title, entries(groups[g.ID]))
	}
	title := "COMMANDS"
	if len(cmd.Groups()) > 0 {
		title = "ADDITIONAL COMMANDS"
	}
	section(w, title, entries(groups[""]))
	section(w, "HELP TOPICS", entries(groups["topics"]))

	section(w, "FLAGS", strings.TrimRight(cmd.LocalFlags().FlagUsages(), "\n"))
	section(w, "INHERITED FLAGS", strings.TrimRight(cmd.InheritedFlags().FlagUsages(), "\n"))
	section(w, "ARGUMENTS", indent(cmd.Annotations[helpArguments]))
	section(w, "JSON OUTPUT", indent(cmd.Annotations[helpJSON]))
	section(w, "EXAMPLES", indent(cmd.Example))
	if cmd.HasAvailableSubCommands() {
		section(w, "LEARN MORE", fmt.Sprintf("  Use `%s <command> --help` for more information about a command.", cmd.CommandPath()))
	}
}

func section(w io.Writer, title, body string) {
	if strings.TrimSpace(body) != "" {
		fmt.Fprintf(w, "\n%s\n%s\n", title, body)
	}
}

// entries lists commands as "name:  what it does", aligned.
func entries(cmds []*cobra.Command) string {
	width := 0
	for _, c := range cmds {
		width = max(width, len(c.Name())+1)
	}
	var b strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, c.Name()+":", c.Short)
	}
	return strings.TrimRight(b.String(), "\n")
}

func indent(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	lines := strings.Split(strings.Trim(text, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "  " + l
		}
	}
	return strings.Join(lines, "\n")
}

func cmpOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// topic returns a help topic: a command that only carries text.
func topic(name, short, text string) *cobra.Command {
	return &cobra.Command{Use: name, Short: short, Long: strings.TrimSpace(text)}
}

// selectorArguments explains, wherever a service is selected, how.
const selectorArguments = `A service is selected by its labels, as LABEL=VALUE:
- one or more, e.g. "cluster=prod team=shop" or "cluster=prod,team=shop";
- "name=SERVICE", which always matches at most one per cluster; or
- none, to choose from every service you can reach.
"tunneler services list" shows each service's labels.`

func helpTopics() []*cobra.Command {
	return []*cobra.Command{
		topic("agents", "Use PostgreSQL efficiently from an agent or script", `
For PostgreSQL, choose a service with "tunneler services list --output json".
Use its cluster and name labels in the commands below.

When each query depends on the last result, start psql in a persistent
terminal with standard input kept open:
  tunneler connect cluster=prod name=shop/postgres -- psql -X -v ON_ERROR_STOP=1 -P pager=off
Send later SQL to that same psql process. Exit psql when the investigation
is done. The connection and temporary account live until then, or until
the session expires.

When the queries are known in advance, put them in batch.sql and run:
  tunneler connect cluster=prod name=shop/postgres -- psql -X -v ON_ERROR_STOP=1 -P pager=off -f batch.sql
That executes the file through one psql connection. Put session settings
such as SET statement_timeout at the start of the file.

Each new "tunneler connect" invocation provisions and removes an account.
Reuse one psql process for related queries. SQL remains audited, and the
command does not print credentials. "--output json" does not convert psql
results to JSON.`),

		topic("environment", "Environment variables", `
TUNNELER_SERVER: the coordinator's URL. Overrides "tunneler config --server".

TUNNELER_CLUSTER: for "start exit", the name of the cluster.

TUNNELER_NO_UPDATE_CHECK: if set, do not check the coordinator for a newer
client version.

Set by "tunneler connect -- COMMAND" for the command it runs.

For a postgres service:

PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE, PGSSLMODE: the connection,
as libpq and most Postgres tools read it.

DATABASE_URL: the same connection as a URL.

For a kubernetes service:

KUBECONFIG: a kubeconfig holding one context, for the cluster. The file is
removed when the command exits.`),

		topic("exit-codes", "Exit codes", `
0: success
1: failure, for a reason not listed here
2: wrong flags or arguments
3: not logged in; a person must run "tunneler auth login"
4: access denied, or no such service or session
5: the selector matches several services; the error lists them
6: the service or the coordinator is unavailable

"tunneler connect -- COMMAND" exits with the exit code of COMMAND.`),

		topic("output", "JSON output for scripts and agents", `
With "--output json", tunneler's own commands:
- write results to stdout as JSON, and nothing else;
- report errors to stderr as {"error", "code", "matches"}; and
- never prompt.

With "tunneler connect -- COMMAND", stdout, stderr, and the exit status
belong to COMMAND. "--output json" does not turn SQL results into JSON.

"code" is one of: usage, not_logged_in, access_denied, ambiguous_selector,
service_unavailable, error. See "tunneler help exit-codes".

"matches" accompanies ambiguous_selector: the services that matched. Add
name=SERVICE to the selector and try again.

"tunneler connect" writes one object once the service can be used.
For postgres, once it accepts connections:
  {"event": "listening", "host", "port", "url", "session", "notice"}
and it then reports connections to stderr, one JSON object per line.
For kubernetes, once the kubeconfig context is written, and it exits:
  {"event": "configured", "context", "kubeconfig", "server", "notice"}
"notice" says that access is audited; show it to the person.

"tunneler auth login" needs a person. It writes
  {"event": "device_code", "verification_uri", "user_code"}
for them to act on, waits, then writes {"event": "logged_in"}.

To run a database command, prefer "tunneler connect -- COMMAND": nothing
has to be parsed and no credentials are shown.

For repeated Postgres queries, see "tunneler help agents". Keep one psql
process open or pass it a SQL file to avoid a new session for each query.`),

		topic("selectors", "Select a service by labels", selectorArguments+`

Every service has these labels, besides those its owners gave it:
- cluster: the cluster it runs in
- kind: postgres or kubernetes
- name: its name, unique in its cluster
- namespace: for services registered in Kubernetes

Grants use the same labels to say who can reach what.`),
	}
}
