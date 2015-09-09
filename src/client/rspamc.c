/*
 * Copyright (c) 2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include "http.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "rspamdclient.h"
#include "utlist.h"

#define DEFAULT_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

static gchar *connect_str = "localhost";
static gchar *password = NULL;
static gchar *ip = NULL;
static gchar *from = NULL;
static gchar *deliver_to = NULL;
static gchar *rcpt = NULL;
static gchar *user = NULL;
static gchar *helo = "localhost.localdomain";
static gchar *hostname = "localhost";
static gchar *classifier = "bayes";
static gchar *local_addr = NULL;
static gchar *execute = NULL;
static gint weight = 0;
static gint flag = 0;
static gint max_requests = 8;
static gdouble timeout = 5.0;
static gboolean pass_all;
static gboolean tty = FALSE;
static gboolean verbose = FALSE;
static gboolean print_commands = FALSE;
static gboolean json = FALSE;
static gboolean headers = FALSE;
static gboolean raw = FALSE;
static gboolean extended_urls = FALSE;
static gboolean mime_output = FALSE;
static gchar *key = NULL;
static GList *children;

static GOptionEntry entries[] =
{
	{ "connect", 'h', 0, G_OPTION_ARG_STRING, &connect_str,
	  "Specify host and port", NULL },
	{ "password", 'P', 0, G_OPTION_ARG_STRING, &password,
	  "Specify control password", NULL },
	{ "classifier", 'c', 0, G_OPTION_ARG_STRING, &classifier,
	  "Classifier to learn spam or ham", NULL },
	{ "weight", 'w', 0, G_OPTION_ARG_INT, &weight,
	  "Weight for fuzzy operations", NULL },
	{ "flag", 'f', 0, G_OPTION_ARG_INT, &flag, "Flag for fuzzy operations",
	  NULL },
	{ "pass-all", 'p', 0, G_OPTION_ARG_NONE, &pass_all, "Pass all filters",
	  NULL },
	{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "More verbose output",
	  NULL },
	{ "ip", 'i', 0, G_OPTION_ARG_STRING, &ip,
	  "Emulate that message was received from specified ip address",
	  NULL },
	{ "user", 'u', 0, G_OPTION_ARG_STRING, &user,
	  "Emulate that message was from specified user", NULL },
	{ "deliver", 'd', 0, G_OPTION_ARG_STRING, &deliver_to,
	  "Emulate that message is delivered to specified user", NULL },
	{ "from", 'F', 0, G_OPTION_ARG_STRING, &from,
	  "Emulate that message is from specified user", NULL },
	{ "rcpt", 'r', 0, G_OPTION_ARG_STRING, &rcpt,
	  "Emulate that message is for specified user", NULL },
	{ "helo", 0, 0, G_OPTION_ARG_STRING, &helo,
	  "Imitate SMTP HELO passing from MTA", NULL },
	{ "hostname", 0, 0, G_OPTION_ARG_STRING, &hostname,
	  "Imitate hostname passing from MTA", NULL },
	{ "timeout", 't', 0, G_OPTION_ARG_DOUBLE, &timeout,
	  "Time in seconds to wait for a reply", NULL },
	{ "bind", 'b', 0, G_OPTION_ARG_STRING, &local_addr,
	  "Bind to specified ip address", NULL },
	{ "commands", 0, 0, G_OPTION_ARG_NONE, &print_commands,
	  "List available commands", NULL },
	{ "json", 'j', 0, G_OPTION_ARG_NONE, &json, "Output json reply", NULL },
	{ "headers", 0, 0, G_OPTION_ARG_NONE, &headers, "Output HTTP headers",
	  NULL },
	{ "raw", 0, 0, G_OPTION_ARG_NONE, &raw, "Output raw reply from rspamd",
	  NULL },
	{ "ucl", 0, 0, G_OPTION_ARG_NONE, &raw, "Output ucl reply from rspamd",
	  NULL },
	{ "max-requests", 'n', 0, G_OPTION_ARG_INT, &max_requests,
	  "Maximum count of parallel requests to rspamd", NULL },
	{ "extended-urls", 0, 0, G_OPTION_ARG_NONE, &extended_urls,
	   "Output urls in extended format", NULL },
	{ "key", 0, 0, G_OPTION_ARG_STRING, &key,
	   "Use specified pubkey to encrypt request", NULL },
	{ "exec", 'e', 0, G_OPTION_ARG_STRING, &execute,
	   "Execute the specified command and pass output to it", NULL },
	{ "mime", 'e', 0, G_OPTION_ARG_NONE, &mime_output,
	   "Write mime body of message with headers instead of just a scan's result", NULL },
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

/* Copy to avoid linking with librspamdserver */
enum rspamd_metric_action {
	METRIC_ACTION_REJECT = 0,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_NOACTION,
	METRIC_ACTION_MAX
};

static void rspamc_symbols_output (FILE *out, ucl_object_t *obj);
static void rspamc_uptime_output (FILE *out, ucl_object_t *obj);
static void rspamc_counters_output (FILE *out, ucl_object_t *obj);
static void rspamc_stat_output (FILE *out, ucl_object_t *obj);

enum rspamc_command_type {
	RSPAMC_COMMAND_UNKNOWN = 0,
	RSPAMC_COMMAND_SYMBOLS,
	RSPAMC_COMMAND_LEARN_SPAM,
	RSPAMC_COMMAND_LEARN_HAM,
	RSPAMC_COMMAND_FUZZY_ADD,
	RSPAMC_COMMAND_FUZZY_DEL,
	RSPAMC_COMMAND_STAT,
	RSPAMC_COMMAND_STAT_RESET,
	RSPAMC_COMMAND_COUNTERS,
	RSPAMC_COMMAND_UPTIME,
	RSPAMC_COMMAND_ADD_SYMBOL,
	RSPAMC_COMMAND_ADD_ACTION
};

struct rspamc_command {
	enum rspamc_command_type cmd;
	const char *name;
	const char *description;
	const char *path;
	gboolean is_controller;
	gboolean is_privileged;
	gboolean need_input;
	void (*command_output_func)(FILE *, ucl_object_t *obj);
} rspamc_commands[] = {
	{
		.cmd = RSPAMC_COMMAND_SYMBOLS,
		.name = "symbols",
		.path = "check",
		.description = "scan message and show symbols (default command)",
		.is_controller = FALSE,
		.is_privileged = FALSE,
		.need_input = TRUE,
		.command_output_func = rspamc_symbols_output
	},
	{
		.cmd = RSPAMC_COMMAND_LEARN_SPAM,
		.name = "learn_spam",
		.path = "learnspam",
		.description = "learn message as spam",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_LEARN_HAM,
		.name = "learn_ham",
		.path = "learnham",
		.description = "learn message as ham",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_FUZZY_ADD,
		.name = "fuzzy_add",
		.path = "fuzzyadd",
		.description =
			"add message to fuzzy storage (check -f and -w options for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_FUZZY_DEL,
		.name = "fuzzy_del",
		.path = "fuzzydel",
		.description =
			"delete message from fuzzy storage (check -f option for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_STAT,
		.name = "stat",
		.path = "stat",
		.description = "show rspamd statistics",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_stat_output,
	},
	{
		.cmd = RSPAMC_COMMAND_STAT_RESET,
		.name = "stat_reset",
		.path = "statreset",
		.description = "show and reset rspamd statistics (useful for graphs)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = rspamc_stat_output
	},
	{
		.cmd = RSPAMC_COMMAND_COUNTERS,
		.name = "counters",
		.path = "counters",
		.description = "display rspamd symbols statistics",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_counters_output
	},
	{
		.cmd = RSPAMC_COMMAND_UPTIME,
		.name = "uptime",
		.path = "auth",
		.description = "show rspamd uptime",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_uptime_output
	},
	{
		.cmd = RSPAMC_COMMAND_ADD_SYMBOL,
		.name = "add_symbol",
		.path = "addsymbol",
		.description = "add or modify symbol settings in rspamd",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_ADD_ACTION,
		.name = "add_action",
		.path = "addaction",
		.description = "add or modify action settings",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = NULL
	}
};

struct rspamc_callback_data {
	struct rspamc_command *cmd;
	gchar *filename;
};

/*
 * Parse command line
 */
static void
read_cmd_line (gint *argc, gchar ***argv)
{
	GError *error = NULL;
	GOptionContext *context;

	/* Prepare parser */
	context = g_option_context_new ("- run rspamc client");
	g_option_context_set_summary (context,
		"Summary:\n  Rspamd client version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);

	/* Parse options */
	if (!g_option_context_parse (context, argc, argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		exit (EXIT_FAILURE);
	}

	if (json) {
		raw = TRUE;
	}
	/* Argc and argv are shifted after this function */
}

/*
 * Check rspamc command from string (used for arguments parsing)
 */
static struct rspamc_command *
check_rspamc_command (const gchar *cmd)
{
	enum rspamc_command_type ct = 0;
	guint i;

	if (g_ascii_strcasecmp (cmd, "SYMBOLS") == 0 ||
		g_ascii_strcasecmp (cmd, "CHECK") == 0 ||
		g_ascii_strcasecmp (cmd, "REPORT") == 0) {
		/* These all are symbols, don't use other commands */
		ct = RSPAMC_COMMAND_SYMBOLS;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN_SPAM") == 0) {
		ct = RSPAMC_COMMAND_LEARN_SPAM;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN_HAM") == 0) {
		ct = RSPAMC_COMMAND_LEARN_HAM;
	}
	else if (g_ascii_strcasecmp (cmd, "FUZZY_ADD") == 0) {
		ct = RSPAMC_COMMAND_FUZZY_ADD;
	}
	else if (g_ascii_strcasecmp (cmd, "FUZZY_DEL") == 0) {
		ct = RSPAMC_COMMAND_FUZZY_DEL;
	}
	else if (g_ascii_strcasecmp (cmd, "STAT") == 0) {
		ct = RSPAMC_COMMAND_STAT;
	}
	else if (g_ascii_strcasecmp (cmd, "STAT_RESET") == 0) {
		ct = RSPAMC_COMMAND_STAT_RESET;
	}
	else if (g_ascii_strcasecmp (cmd, "COUNTERS") == 0) {
		ct = RSPAMC_COMMAND_COUNTERS;
	}
	else if (g_ascii_strcasecmp (cmd, "UPTIME") == 0) {
		ct = RSPAMC_COMMAND_UPTIME;
	}
	else if (g_ascii_strcasecmp (cmd, "ADD_SYMBOL") == 0) {
		ct = RSPAMC_COMMAND_ADD_SYMBOL;
	}
	else if (g_ascii_strcasecmp (cmd, "ADD_ACTION") == 0) {
		ct = RSPAMC_COMMAND_ADD_ACTION;
	}

	for (i = 0; i < G_N_ELEMENTS (rspamc_commands); i++) {
		if (rspamc_commands[i].cmd == ct) {
			return &rspamc_commands[i];
		}
	}

	return NULL;
}

static void
print_commands_list (void)
{
	guint i;

	rspamd_fprintf (stdout, "Rspamc commands summary:\n");
	for (i = 0; i < G_N_ELEMENTS (rspamc_commands); i++) {
		rspamd_fprintf (stdout,
			"  %10s (%7s%1s)\t%s\n",
			rspamc_commands[i].name,
			rspamc_commands[i].is_controller ? "control" : "normal",
			rspamc_commands[i].is_privileged ? "*" : "",
			rspamc_commands[i].description);
	}
	rspamd_fprintf (stdout,
		"\n* is for privileged commands that may need password (see -P option)\n");
	rspamd_fprintf (stdout,
		"control commands use port 11334 while normal use 11333 by default (see -h option)\n");
}


static void
add_options (GHashTable *opts)
{
	GString *numbuf;

	if (ip != NULL) {
		g_hash_table_insert (opts, "Ip", ip);
	}
	if (from != NULL) {
		g_hash_table_insert (opts, "From", from);
	}
	if (user != NULL) {
		g_hash_table_insert (opts, "User", user);
	}
	if (rcpt != NULL) {
		g_hash_table_insert (opts, "Rcpt", rcpt);
	}
	if (deliver_to != NULL) {
		g_hash_table_insert (opts, "Deliver-To", deliver_to);
	}
	if (helo != NULL) {
		g_hash_table_insert (opts, "Helo", helo);
	}
	if (hostname != NULL) {
		g_hash_table_insert (opts, "Hostname", hostname);
	}
	if (password != NULL) {
		g_hash_table_insert (opts, "Password", password);
	}
	if (pass_all) {
		g_hash_table_insert (opts, "Pass", "all");
	}
	if (weight != 0) {
		numbuf = g_string_sized_new (8);
		rspamd_printf_gstring (numbuf, "%d", weight);
		g_hash_table_insert (opts, "Weight", numbuf->str);
	}
	if (flag != 0) {
		numbuf = g_string_sized_new (8);
		rspamd_printf_gstring (numbuf, "%d", flag);
		g_hash_table_insert (opts, "Flag", numbuf->str);
	}
	if (extended_urls) {
		g_hash_table_insert (opts, "URL-Format", "extended");
	}
}

static void
rspamc_symbol_output (FILE *out, const ucl_object_t *obj)
{
	const ucl_object_t *val, *cur;
	ucl_object_iter_t it = NULL;
	gboolean first = TRUE;

	rspamd_fprintf (out, "Symbol: %s ", ucl_object_key (obj));
	val = ucl_object_find_key (obj, "score");

	if (val != NULL) {
		rspamd_fprintf (out, "(%.2f)", ucl_object_todouble (val));
	}
	val = ucl_object_find_key (obj, "options");
	if (val != NULL && val->type == UCL_ARRAY) {
		rspamd_fprintf (out, "[");

		while ((cur = ucl_iterate_object (val, &it, TRUE)) != NULL) {
			if (first) {
				rspamd_fprintf (out, "%s", ucl_object_tostring (cur));
				first = FALSE;
			}
			else {
				rspamd_fprintf (out, ", %s", ucl_object_tostring (cur));
			}
		}
		rspamd_fprintf (out, "]");
	}
	rspamd_fprintf (out, "\n");
}

static void
rspamc_metric_output (FILE *out, const ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	gdouble score = 0, required_score = 0;
	gint got_scores = 0;

	rspamd_fprintf (out, "[Metric: %s]\n", ucl_object_key (obj));

	while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
		if (g_ascii_strcasecmp (ucl_object_key (cur), "is_spam") == 0) {
			rspamd_fprintf (out, "Spam: %s\n", ucl_object_toboolean (cur) ?
				"true" : "false");
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "score") == 0) {
			score = ucl_object_todouble (cur);
			got_scores++;
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur),
			"required_score") == 0) {
			required_score = ucl_object_todouble (cur);
			got_scores++;
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "action") == 0) {
			rspamd_fprintf (out, "Action: %s\n", ucl_object_tostring (cur));
		}
		else if (cur->type == UCL_OBJECT) {
			rspamc_symbol_output (out, cur);
		}
		if (got_scores == 2) {
			rspamd_fprintf (out,
				"Score: %.2f / %.2f\n",
				score,
				required_score);
			got_scores = 0;
		}
	}
}

static void
rspamc_symbols_output (FILE *out, ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL, mit = NULL;
	const ucl_object_t *cur, *cmesg;
	gchar *emitted;

	while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
		if (g_ascii_strcasecmp (ucl_object_key (cur), "message-id") == 0) {
			rspamd_fprintf (out, "Message-ID: %s\n", ucl_object_tostring (
					cur));
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "queue-id") == 0) {
			rspamd_fprintf (out, "Queue-ID: %s\n",
				ucl_object_tostring (cur));
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "urls") == 0) {
			if (!extended_urls) {
				emitted = ucl_object_emit (cur, UCL_EMIT_JSON_COMPACT);
			}
			else {
				emitted = ucl_object_emit (cur, UCL_EMIT_JSON);
			}
			rspamd_fprintf (out, "Urls: %s\n", emitted);
			free (emitted);
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "emails") == 0) {
			emitted = ucl_object_emit (cur, UCL_EMIT_JSON_COMPACT);
			rspamd_fprintf (out, "Emails: %s\n", emitted);
			free (emitted);
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "error") == 0) {
			rspamd_fprintf (out, "Scan error: %s\n", ucl_object_tostring (
					cur));
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "messages") == 0) {
			if (cur->type == UCL_ARRAY) {
				mit = NULL;
				while ((cmesg = ucl_iterate_object (cur, &mit, true)) != NULL) {
					rspamd_fprintf (out, "Message: %s\n",
							ucl_object_tostring (cmesg));
				}
			}
		}
		else if (cur->type == UCL_OBJECT) {
			/* Parse metric */
			rspamc_metric_output (out, cur);
		}
	}
}

static void
rspamc_uptime_output (FILE *out, ucl_object_t *obj)
{
	const ucl_object_t *elt;
	int64_t seconds, days, hours, minutes;

	elt = ucl_object_find_key (obj, "version");
	if (elt != NULL) {
		rspamd_fprintf (out, "Rspamd version: %s\n", ucl_object_tostring (
				elt));
	}

	elt = ucl_object_find_key (obj, "uptime");
	if (elt != NULL) {
		rspamd_printf ("Uptime: ");
		seconds = ucl_object_toint (elt);
		if (seconds >= 2 * 3600) {
			days = seconds / 86400;
			hours = seconds / 3600 - days * 24;
			minutes = seconds / 60 - hours * 60 - days * 1440;
			rspamd_printf ("%L day%s %L hour%s %L minute%s\n", days,
				days > 1 ? "s" : "", hours, hours > 1 ? "s" : "",
				minutes, minutes > 1 ? "s" : "");
		}
		/* If uptime is less than 1 minute print only seconds */
		else if (seconds / 60 == 0) {
			rspamd_printf ("%L second%s\n", (gint)seconds,
				(gint)seconds > 1 ? "s" : "");
		}
		/* Else print the minutes and seconds. */
		else {
			hours = seconds / 3600;
			minutes = seconds / 60 - hours * 60;
			seconds -= hours * 3600 + minutes * 60;
			rspamd_printf ("%L hour %L minute%s %L second%s\n", hours,
				minutes, minutes > 1 ? "s" : "",
				seconds, seconds > 1 ? "s" : "");
		}
	}
}

static void
rspamc_counters_output (FILE *out, ucl_object_t *obj)
{
	const ucl_object_t *cur, *sym, *weight, *freq, *tim;
	ucl_object_iter_t iter = NULL;
	gchar fmt_buf[64], dash_buf[82];
	gint l, max_len = INT_MIN, i;

	if (obj->type != UCL_ARRAY) {
		rspamd_printf ("Bad output\n");
		return;
	}
	/* Find maximum width of symbol's name */
	while ((cur = ucl_iterate_object (obj, &iter, true)) != NULL) {
		sym = ucl_object_find_key (cur, "symbol");
		if (sym != NULL) {
			l = sym->len;
			if (l > max_len) {
				max_len = MIN (40, l);
			}
		}
	}

	rspamd_snprintf (fmt_buf, sizeof (fmt_buf),
		"| %%3s | %%%ds | %%6s | %%9s | %%9s |\n", max_len);
	memset (dash_buf, '-', 40 + max_len);
	dash_buf[40 + max_len] = '\0';

	printf ("Symbols cache\n");
	printf (" %s \n", dash_buf);
	if (tty) {
		printf ("\033[1m");
	}
	printf (fmt_buf, "Pri", "Symbol", "Weight", "Frequency", "Avg. time");
	if (tty) {
		printf ("\033[0m");
	}
	rspamd_snprintf (fmt_buf, sizeof (fmt_buf),
		"| %%3d | %%%ds | %%6.1f | %%9d | %%9.3f |\n", max_len);

	iter = NULL;
	i = 0;
	while ((cur = ucl_iterate_object (obj, &iter, true)) != NULL) {
		printf (" %s \n", dash_buf);
		sym = ucl_object_find_key (cur, "symbol");
		weight = ucl_object_find_key (cur, "weight");
		freq = ucl_object_find_key (cur, "frequency");
		tim = ucl_object_find_key (cur, "time");
		if (sym && weight && freq && tim) {
			printf (fmt_buf, i,
				ucl_object_tostring (sym),
				ucl_object_todouble (weight),
				(gint)ucl_object_toint (freq),
				ucl_object_todouble (tim));
		}
		i++;
	}
	printf (" %s \n", dash_buf);
}

static void
rspamc_stat_actions (ucl_object_t *obj, GString *out, gint64 scanned)
{
	const ucl_object_t *actions = ucl_object_find_key (obj, "actions"), *cur;
	ucl_object_iter_t iter = NULL;
	gint64 spam, ham;

	if (actions && ucl_object_type (actions) == UCL_OBJECT) {
		while ((cur = ucl_iterate_object (actions, &iter, true)) != NULL) {
			gint64 cnt = ucl_object_toint (cur);
			rspamd_printf_gstring (out, "Messages with action %s: %L"
				", %.2f%%\n", ucl_object_key (cur), cnt,
				((gdouble)cnt / (gdouble)scanned) * 100.);
		}
	}

	spam = ucl_object_toint (ucl_object_find_key (obj, "spam_count"));
	ham = ucl_object_toint (ucl_object_find_key (obj, "ham_count"));
	rspamd_printf_gstring (out, "Messages treated as spam: %L, %.2f%%\n", spam,
		((gdouble)spam / (gdouble)scanned) * 100.);
	rspamd_printf_gstring (out, "Messages treated as ham: %L, %.2f%%\n", ham,
		((gdouble)ham / (gdouble)scanned) * 100.);
}

static void
rspamc_stat_statfile (const ucl_object_t *obj, GString *out)
{
	gint64 version, size, blocks, used_blocks, nlanguages, nusers;
	const gchar *label, *symbol, *type;

	version = ucl_object_toint (ucl_object_find_key (obj, "revision"));
	size = ucl_object_toint (ucl_object_find_key (obj, "size"));
	blocks = ucl_object_toint (ucl_object_find_key (obj, "total"));
	used_blocks = ucl_object_toint (ucl_object_find_key (obj, "used"));
	label = ucl_object_tostring (ucl_object_find_key (obj, "label"));
	symbol = ucl_object_tostring (ucl_object_find_key (obj, "symbol"));
	type = ucl_object_tostring (ucl_object_find_key (obj, "type"));
	nlanguages = ucl_object_toint (ucl_object_find_key (obj, "languages"));
	nusers = ucl_object_toint (ucl_object_find_key (obj, "users"));

	if (label) {
		rspamd_printf_gstring (out, "Statfile: %s <%s> type: %s; ", symbol,
				label, type);
	}
	else {
		rspamd_printf_gstring (out, "Statfile: %s type: %s; ", symbol, type);
	}
	rspamd_printf_gstring (out, "length: %HL; free blocks: %HL; total blocks: %HL; "
			"free: %.2f%%; learned: %L; users: %L; languages: %L\n",
			size,
			blocks - used_blocks, blocks,
			blocks > 0 ? (blocks - used_blocks) * 100.0 / (gdouble)blocks : 0,
			version,
			nusers, nlanguages);
}

static void
rspamc_stat_output (FILE *out, ucl_object_t *obj)
{
	GString *out_str;
	ucl_object_iter_t iter = NULL;
	const ucl_object_t *st, *cur;
	gint64 scanned;

	out_str = g_string_sized_new (BUFSIZ);

	scanned = ucl_object_toint (ucl_object_find_key (obj, "scanned"));
	rspamd_printf_gstring (out_str, "Messages scanned: %L\n",
		scanned);

	if (scanned > 0) {
		rspamc_stat_actions (obj, out_str, scanned);
	}

	rspamd_printf_gstring (out_str, "Messages learned: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "learned")));
	rspamd_printf_gstring (out_str, "Connections count: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "connections")));
	rspamd_printf_gstring (out_str, "Control connections count: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "control_connections")));
	/* Pools */
	rspamd_printf_gstring (out_str, "Pools allocated: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "pools_allocated")));
	rspamd_printf_gstring (out_str, "Pools freed: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "pools_freed")));
	rspamd_printf_gstring (out_str, "Bytes allocated: %HL\n",
		ucl_object_toint (ucl_object_find_key (obj, "bytes_allocated")));
	rspamd_printf_gstring (out_str, "Memory chunks allocated: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "chunks_allocated")));
	rspamd_printf_gstring (out_str, "Shared chunks allocated: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "shared_chunks_allocated")));
	rspamd_printf_gstring (out_str, "Chunks freed: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "chunks_freed")));
	rspamd_printf_gstring (out_str, "Oversized chunks: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "chunks_oversized")));
	/* Fuzzy */
	rspamd_printf_gstring (out_str, "Fuzzy hashes stored: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "fuzzy_stored")));
	rspamd_printf_gstring (out_str, "Fuzzy hashes expired: %L\n",
		ucl_object_toint (ucl_object_find_key (obj, "fuzzy_expired")));

	st = ucl_object_find_key (obj, "fuzzy_checked");
	if (st != NULL && ucl_object_type (st) == UCL_ARRAY) {
		rspamd_printf_gstring (out_str, "Fuzzy hashes checked: ");
		iter = NULL;

		while ((cur = ucl_iterate_object (st, &iter, true)) != NULL) {
			rspamd_printf_gstring (out_str, "%hL ", ucl_object_toint (cur));
		}

		rspamd_printf_gstring (out_str, "\n");
	}

	st = ucl_object_find_key (obj, "fuzzy_found");
	if (st != NULL && ucl_object_type (st) == UCL_ARRAY) {
		rspamd_printf_gstring (out_str, "Fuzzy hashes found: ");
		iter = NULL;

		while ((cur = ucl_iterate_object (st, &iter, true)) != NULL) {
			rspamd_printf_gstring (out_str, "%hL ", ucl_object_toint (cur));
		}

		rspamd_printf_gstring (out_str, "\n");
	}

	st = ucl_object_find_key (obj, "statfiles");
	if (st != NULL && ucl_object_type (st) == UCL_ARRAY) {
		iter = NULL;

		while ((cur = ucl_iterate_object (st, &iter, true)) != NULL) {
			rspamc_stat_statfile (cur, out_str);
		}
	}
	rspamd_printf_gstring (out_str, "Total learns: %L\n",
			ucl_object_toint (ucl_object_find_key (obj, "total_learns")));

	rspamd_fprintf (out, "%v", out_str);
}

static void
rspamc_output_headers (FILE *out, struct rspamd_http_message *msg)
{
	struct rspamd_http_header *h;

	LL_FOREACH (msg->headers, h)
	{
		rspamd_fprintf (out, "%v: %v\n", h->name, h->value);
	}
	rspamd_fprintf (out, "\n");
}

static gboolean
rspamd_action_from_str (const gchar *data, gint *result)
{
	if (g_ascii_strncasecmp (data, "reject", sizeof ("reject") - 1) == 0) {
		*result = METRIC_ACTION_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "greylist",
		sizeof ("greylist") - 1) == 0) {
		*result = METRIC_ACTION_GREYLIST;
	}
	else if (g_ascii_strncasecmp (data, "add_header", sizeof ("add_header") -
		1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite_subject",
		sizeof ("rewrite_subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (g_ascii_strncasecmp (data, "add header", sizeof ("add header") -
			1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite subject",
			sizeof ("rewrite subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (g_ascii_strncasecmp (data, "soft_reject",
			sizeof ("soft_reject") - 1) == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "soft reject",
			sizeof ("soft reject") - 1) == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "no_action",
			sizeof ("soft_reject") - 1) == 0) {
		*result = METRIC_ACTION_NOACTION;
	}
	else if (g_ascii_strncasecmp (data, "no action",
			sizeof ("soft reject") - 1) == 0) {
		*result = METRIC_ACTION_NOACTION;
	}
	else {
		return FALSE;
	}
	return TRUE;
}

static void
rspamc_mime_output (FILE *out, ucl_object_t *result, GString *input, GError *err)
{
	GMimeStream *stream;
	GByteArray ar;
	GMimeParser *parser;
	GMimeMessage *message;
	const ucl_object_t *cur, *metric, *res;
	ucl_object_iter_t it = NULL;
	const gchar *action = "no action";
	GString *symbuf, *folded_symbuf;
	gint act;
	gdouble score = 0.0, required_score = 0.0;
	gchar scorebuf[32];
	gboolean is_spam = FALSE;
	const gchar *hdr_scanned, *hdr_spam;
	gchar *json_header, *json_header_encoded, *sc;

	ar.data = input->str;
	ar.len = input->len;

	stream = g_mime_stream_mem_new_with_byte_array (&ar);
	g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (stream), FALSE);
	parser = g_mime_parser_new_with_stream (stream);
	g_object_unref (stream);

	message = g_mime_parser_construct_message (parser);

	if (message == NULL) {
		rspamd_fprintf (stderr,"cannot construct mime from stream");
		return;
	}

	if (result) {
		metric = ucl_object_find_key (result, "default");

		if (metric != NULL) {
			res = ucl_object_find_key (metric, "action");

			if (res) {
				action = ucl_object_tostring (res);
			}

			res = ucl_object_find_key (metric, "score");
			if (res) {
				score = ucl_object_todouble (res);
			}

			res = ucl_object_find_key (metric, "required_score");
			if (res) {
				required_score = ucl_object_todouble (res);
			}
		}

		rspamd_action_from_str (action, &act);

		if (act < METRIC_ACTION_GREYLIST) {
			is_spam = TRUE;
		}

		hdr_scanned = "rspamc " RVERSION;
		g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Scanner",
				hdr_scanned);
		if (is_spam) {
			hdr_spam = "yes";
			g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam", hdr_spam);
		}

		g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Action",
				action);

		rspamd_snprintf (scorebuf, sizeof (scorebuf), "%.2f / %.2f", score,
				required_score);
		g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Score",
				scorebuf);

		/* SA style stars header */
		for (sc = scorebuf; sc < scorebuf + sizeof (scorebuf) - 1 && score > 0;
			 sc ++, score -= 1.0) {
			*sc = '*';
		}

		*sc = '\0';
		g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Level",
				scorebuf);

		/* Short description of all symbols */
		symbuf = g_string_sized_new (64);

		while ((cur = ucl_iterate_object (metric, &it, true)) != NULL) {

			if (ucl_object_type (cur) == UCL_OBJECT) {
				rspamd_printf_gstring (symbuf, "%s,", ucl_object_key (cur));
			}
		}
		/* Trim the last comma */
		if (symbuf->str[symbuf->len - 1] == ',') {
			g_string_erase (symbuf, symbuf->len - 1, 1);
		}

		folded_symbuf = rspamd_header_value_fold ("X-Spam-Symbols", symbuf->str);
		g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Symbols",
				symbuf->str);
		g_string_free (folded_symbuf, TRUE);
		g_string_free (symbuf, TRUE);

		if (json || raw) {
			/* We also append json data as a specific header */
			if (json) {
				json_header = ucl_object_emit (result, UCL_EMIT_JSON);
			}
			else {
				json_header = ucl_object_emit (result, UCL_EMIT_CONFIG);
			}

			json_header_encoded = rspamd_encode_base64_fold (json_header,
					strlen (json_header), 60, NULL);
			free (json_header);
			g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Result",
					json_header_encoded);
			g_free (json_header_encoded);
		}

		ucl_object_unref (result);
	}
	else {
		hdr_scanned = "rspamc " RVERSION;
		g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Scanner",
				hdr_scanned);

		if (err && err->message) {
			g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Error",
					err->message);
		}
		else {
			g_mime_object_append_header (GMIME_OBJECT (message), "X-Spam-Error",
					"Unknown error");
		}
	}

	/* Write message */
	stream = g_mime_stream_file_new (out);
	g_mime_stream_file_set_owner (GMIME_STREAM_FILE (stream), FALSE);
	g_mime_object_write_to_stream (GMIME_OBJECT (message), stream);
	g_object_unref (stream);
	g_object_unref (message);
	g_object_unref (parser);
}

static void
rspamc_client_execute_cmd (struct rspamc_command *cmd, ucl_object_t *result,
		GString *input, GError *err)
{
	gchar **eargv;
	gint eargc, infd, outfd, errfd;
	GError *exec_err = NULL;
	GPid cld;
	FILE *out;
	gchar *ucl_out;

	if (!g_shell_parse_argv (execute, &eargc, &eargv, &err)) {
		rspamd_fprintf (stderr, "Cannot execute %s: %e", execute, err);
		g_error_free (err);

		return;
	}

	if (!g_spawn_async_with_pipes (NULL, eargv, NULL,
			G_SPAWN_SEARCH_PATH|G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &cld,
			&infd, &outfd, &errfd, &exec_err)) {

		rspamd_fprintf (stderr, "Cannot execute %s: %e", execute, exec_err);
		g_error_free (exec_err);
	}
	else {
		children = g_list_prepend (children, GSIZE_TO_POINTER (cld));
		out = fdopen (infd, "w");

		if (cmd->cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			rspamc_mime_output (out, result, input, err);
		}
		else if (result) {
			if (raw || cmd->command_output_func == NULL) {
				if (json) {
					ucl_out = ucl_object_emit (result, UCL_EMIT_JSON);
				}
				else {
					ucl_out = ucl_object_emit (result, UCL_EMIT_CONFIG);
				}
				rspamd_fprintf (out, "%s", ucl_out);
				free (ucl_out);
			}
			else {
				cmd->command_output_func (out, result);
			}

			ucl_object_unref (result);
		}
		else {
			rspamd_fprintf (out, "%e\n", err);
		}

		fflush (out);

		fclose (out);
	}

	g_strfreev (eargv);
}

static void
rspamc_client_cb (struct rspamd_client_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *name, ucl_object_t *result, GString *input,
	gpointer ud, GError *err)
{
	gchar *ucl_out;
	struct rspamc_callback_data *cbdata = (struct rspamc_callback_data *)ud;
	struct rspamc_command *cmd;
	FILE *out = stdout;

	cmd = cbdata->cmd;

	if (execute) {
		/* Pass all to the external command */
		rspamc_client_execute_cmd (cmd, result, input, err);
	}
	else {

		if (cmd->cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			rspamc_mime_output (out, result, input, err);
		}
		else {
			if (cmd->need_input) {
				rspamd_fprintf (out, "Results for file: %s\n", cbdata->filename);
			}
			else {
				rspamd_fprintf (out, "Results for command: %s\n", cmd->name);
			}

			if (result != NULL) {
				if (headers && msg != NULL) {
					rspamc_output_headers (out, msg);
				}
				if (raw || cmd->command_output_func == NULL) {
					if (json) {
						ucl_out = ucl_object_emit (result, UCL_EMIT_JSON);
					}
					else {
						ucl_out = ucl_object_emit (result, UCL_EMIT_CONFIG);
					}
					rspamd_fprintf (out, "%s", ucl_out);
					free (ucl_out);
				}
				else {
					cmd->command_output_func (out, result);
				}

				ucl_object_unref (result);
			}
			else if (err != NULL) {
				rspamd_fprintf (out, "%s\n", err->message);

				if (json && msg != NULL && msg->body != NULL) {
					/* We can also output the resulting json */
					rspamd_fprintf (out, "%v\n", msg->body);
				}
			}
		}

		rspamd_fprintf (out, "\n");
		fflush (out);
	}

	rspamd_client_destroy (conn);
	g_free (cbdata->filename);
	g_slice_free1 (sizeof (struct rspamc_callback_data), cbdata);
}

static void
rspamc_process_input (struct event_base *ev_base, struct rspamc_command *cmd,
	FILE *in, const gchar *name, GHashTable *attrs)
{
	struct rspamd_client_connection *conn;
	gchar **connectv;
	guint16 port;
	GError *err = NULL;
	struct rspamc_callback_data *cbdata;

	connectv = g_strsplit_set (connect_str, ":", -1);

	if (connectv == NULL || connectv[0] == NULL) {
		fprintf (stderr, "bad connect string: %s\n", connect_str);
		exit (EXIT_FAILURE);
	}

	if (connectv[1] != NULL) {
		port = strtoul (connectv[1], NULL, 10);
	}
	else if (*connectv[0] != '/') {
		port = cmd->is_controller ? DEFAULT_CONTROL_PORT : DEFAULT_PORT;
	}
	else {
		/* Unix socket */
		port = 0;
	}

	conn = rspamd_client_init (ev_base, connectv[0], port, timeout, key);
	g_strfreev (connectv);

	if (conn != NULL) {
		cbdata = g_slice_alloc (sizeof (struct rspamc_callback_data));
		cbdata->cmd = cmd;
		cbdata->filename = g_strdup (name);
		if (cmd->need_input) {
			rspamd_client_command (conn, cmd->path, attrs, in, rspamc_client_cb,
				cbdata, &err);
		}
		else {
			rspamd_client_command (conn,
				cmd->path,
				attrs,
				NULL,
				rspamc_client_cb,
				cbdata,
				&err);
		}
	}
}

static void
rspamc_process_dir (struct event_base *ev_base, struct rspamc_command *cmd,
	const gchar *name, GHashTable *attrs)
{
	DIR *d;
	gint cur_req = 0;
	struct dirent *ent;
#if defined(__sun)
	struct stat sb;
#endif
	FILE *in;
	char filebuf[PATH_MAX];

	d = opendir (name);

	if (d != NULL) {
		while ((ent = readdir (d))) {
			rspamd_snprintf (filebuf, sizeof (filebuf), "%s%c%s",
					name, G_DIR_SEPARATOR, ent->d_name);
#if defined(__sun)
			if (stat (filebuf, &sb)) continue;
			if (S_ISREG (sb.st_mode)) {
#else
			if (ent->d_type == DT_REG || ent->d_type == DT_UNKNOWN) {
#endif
				if (access (filebuf, R_OK) != -1) {
					in = fopen (filebuf, "r");
					if (in == NULL) {
						fprintf (stderr, "cannot open file %s\n", filebuf);
						exit (EXIT_FAILURE);
					}
					rspamc_process_input (ev_base, cmd, in, filebuf, attrs);
					cur_req++;
					fclose (in);
					if (cur_req >= max_requests) {
						cur_req = 0;
						/* Wait for completion */
						event_base_loop (ev_base, 0);
					}
				}
			}
		}
	}
	else {
		fprintf (stderr, "cannot open directory %s\n", name);
		exit (EXIT_FAILURE);
	}

	closedir (d);
	event_base_loop (ev_base, 0);
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gint i, start_argc, cur_req = 0, res;
	GHashTable *kwattrs;
	GList *cur;
	GPid cld;
	struct rspamc_command *cmd;
	FILE *in = NULL;
	struct event_base *ev_base;
	struct stat st;
	struct sigaction sigpipe_act;

	kwattrs = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);

	read_cmd_line (&argc, &argv);

	tty = isatty (STDOUT_FILENO);

	if (print_commands) {
		print_commands_list ();
		exit (EXIT_SUCCESS);
	}

	ev_base = event_init ();
	g_mime_init (0);

	/* Ignore sigpipe */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);

	/* Now read other args from argc and argv */
	if (argc == 1) {
		start_argc = argc;
		in = stdin;
		cmd = check_rspamc_command ("symbols");
	}
	else if (argc == 2) {
		/* One argument is whether command or filename */
		if ((cmd = check_rspamc_command (argv[1])) != NULL) {
			start_argc = argc;
			in = stdin;
		}
		else {
			cmd = check_rspamc_command ("symbols"); /* Symbols command */
			start_argc = 1;
		}
	}
	else {
		if ((cmd = check_rspamc_command (argv[1])) != NULL) {
			/* In case of command read arguments starting from 2 */
			if (cmd->cmd == RSPAMC_COMMAND_ADD_SYMBOL || cmd->cmd ==
				RSPAMC_COMMAND_ADD_ACTION) {
				if (argc < 4 || argc > 5) {
					fprintf (stderr, "invalid arguments\n");
					exit (EXIT_FAILURE);
				}
				if (argc == 5) {
					g_hash_table_insert (kwattrs, "metric", argv[2]);
					g_hash_table_insert (kwattrs, "name",	argv[3]);
					g_hash_table_insert (kwattrs, "value",	argv[4]);
				}
				else {
					g_hash_table_insert (kwattrs, "name",  argv[2]);
					g_hash_table_insert (kwattrs, "value", argv[3]);
				}
				start_argc = argc;
			}
			else {
				start_argc = 2;
			}
		}
		else {
			cmd = check_rspamc_command ("symbols");
			start_argc = 1;
		}
	}

	add_options (kwattrs);

	if (start_argc == argc) {
		/* Do command without input or with stdin */
		rspamc_process_input (ev_base, cmd, in, "stdin", kwattrs);
	}
	else {
		for (i = start_argc; i < argc; i++) {
			if (stat (argv[i], &st) == -1) {
				fprintf (stderr, "cannot stat file %s\n", argv[i]);
				exit (EXIT_FAILURE);
			}
			if (S_ISDIR (st.st_mode)) {
				/* Directories are processed with a separate limit */
				rspamc_process_dir (ev_base, cmd, argv[i], kwattrs);
				cur_req = 0;
			}
			else {
				in = fopen (argv[i], "r");
				if (in == NULL) {
					fprintf (stderr, "cannot open file %s\n", argv[i]);
					exit (EXIT_FAILURE);
				}
				rspamc_process_input (ev_base, cmd, in, argv[i], kwattrs);
				cur_req++;
				fclose (in);
			}
			if (cur_req >= max_requests) {
				cur_req = 0;
				/* Wait for completion */
				event_base_loop (ev_base, 0);
			}
		}
	}

	event_base_loop (ev_base, 0);

	g_hash_table_destroy (kwattrs);
	g_mime_shutdown ();

	/* Wait for children processes */
	cur = g_list_first (children);

	while (cur) {
		cld = GPOINTER_TO_SIZE (cur->data);

		if (waitpid (cld, &res, 0) == -1) {
			fprintf (stderr, "Cannot wait for %d: %s", (gint)cld,
					strerror (errno));
		}

		cur = g_list_next (cur);
	}

	if (children != NULL) {
		g_list_free (children);
	}

	return 0;
}
