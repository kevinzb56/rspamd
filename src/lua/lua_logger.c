/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "lua_common.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_private.h"

/***
 * @module rspamd_logger
 * Rspamd logger module is used to log messages from LUA API to the main rspamd logger.
 * It supports legacy and modern interfaces allowing highly customized an convenient log functions.
 * Here is an example of logger usage:
 * @example
local rspamd_logger = require "rspamd_logger"

local a = 'string'
local b = 1.5
local c = 1
local d = {
	'aa',
	1,
	'bb'
}
local e = {
	key = 'value',
	key2 = 1.0
}

-- New extended interface
-- %<number> means numeric arguments and %s means the next argument
-- for example %1, %2, %s: %s would mean the third argument

rspamd_logger.info('a=%1, b=%2, c=%3, d=%4, e=%s', a, b, c, d, e)
-- Output: a=string, b=1.50000, c=1, d={[1] = aa, [2] = 1, [3] = bb} e={[key]=value, [key2]=1.0}

-- Create string using logger API
local str = rspamd_logger.slog('a=%1, b=%2, c=%3, d=%4, e=%5', a, b, c, d, e)

print(str)
-- Output: a=string, b=1.50000, c=1, d={[1] = aa, [2] = 1, [3] = bb} e={[key]=value, [key2]=1.0}
 */

/* Logger methods */
/***
 * @function logger.err(msg)
 * Log message as an error
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF(logger, err);
/***
 * @function logger.warn(msg)
 * Log message as a warning
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF(logger, warn);
/***
 * @function logger.info(msg)
 * Log message as an informational message
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF(logger, info);
/***
 * @function logger.message(msg)
 * Log message as an notice message
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF(logger, message);
/***
 * @function logger.debug(msg)
 * Log message as a debug message
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF(logger, debug);
/***
 * @function logger.errx(fmt[, args)
 * Extended interface to make an error log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, errx);
/***
 * @function logger.warn(fmt[, args)
 * Extended interface to make a warning log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, warnx);
/***
 * @function logger.infox(fmt[, args)
 * Extended interface to make an informational log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, infox);
/***
 * @function logger.infox(fmt[, args)
 * Extended interface to make an informational log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, messagex);
/***
 * @function logger.debugx(fmt[, args)
 * Extended interface to make a debug log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, debugx);

/***
 * @function logger.debugm(module, id, fmt[, args)
 * Extended interface to make a debug log message
 * @param {string} module debug module
 * @param {task|cfg|pool|string} id id to log
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, debugm);
/***
 * @function logger.slog(fmt[, args)
 * Create string replacing percent params with corresponding arguments
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 * @return {string} string with percent parameters substituted
 */
LUA_FUNCTION_DEF(logger, slog);

/***
 * @function logger.logx(level, module, id, fmt[, args)
 * Extended interface to make a generic log message on any level
 * @param {number} log level as a number (see GLogLevelFlags enum for values)
 * @param {task|cfg|pool|string} id id to log
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF(logger, logx);

/***
 * @function logger.log_level()
 * Returns log level for a logger
 * @return {string} current log level
 */
LUA_FUNCTION_DEF(logger, log_level);

static const struct luaL_reg loggerlib_f[] = {
	LUA_INTERFACE_DEF(logger, err),
	LUA_INTERFACE_DEF(logger, warn),
	LUA_INTERFACE_DEF(logger, message),
	{"msg", lua_logger_message},
	LUA_INTERFACE_DEF(logger, info),
	LUA_INTERFACE_DEF(logger, debug),
	LUA_INTERFACE_DEF(logger, errx),
	LUA_INTERFACE_DEF(logger, warnx),
	LUA_INTERFACE_DEF(logger, infox),
	LUA_INTERFACE_DEF(logger, messagex),
	{"msgx", lua_logger_messagex},
	LUA_INTERFACE_DEF(logger, debugx),
	LUA_INTERFACE_DEF(logger, debugm),
	LUA_INTERFACE_DEF(logger, slog),
	LUA_INTERFACE_DEF(logger, logx),
	LUA_INTERFACE_DEF(logger, log_level),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}};

static gsize
lua_logger_out_type(lua_State *L, int pos, char *outbuf,
						  gsize len, struct lua_logger_trace *trace,
						  enum lua_logger_escape_type esc_type);

static void
lua_common_log_line(GLogLevelFlags level,
					lua_State *L,
					const char *msg,
					const char *uid,
					const char *module,
					int stack_level)
{
	lua_Debug d;
	char func_buf[128], *p;

	if (lua_getstack(L, stack_level, &d) == 1) {
		(void) lua_getinfo(L, "Sl", &d);
		if ((p = strrchr(d.short_src, '/')) == NULL) {
			p = d.short_src;
		}
		else {
			p++;
		}

		if (strlen(p) > 30) {
			rspamd_snprintf(func_buf, sizeof(func_buf), "%27s...:%d", p,
							d.currentline);
		}
		else {
			rspamd_snprintf(func_buf, sizeof(func_buf), "%s:%d", p,
							d.currentline);
		}

		p = func_buf;
	}
	else {
		p = (char *) G_STRFUNC;
	}

	rspamd_common_log_function(NULL,
						   level,
						   module,
						   uid,
						   p,
						   "%s",
						   msg);
}

/*** Logger interface ***/
static int
lua_logger_err(lua_State *L)
{
	return lua_logger_errx(L);
}

static int
lua_logger_warn(lua_State *L)
{
	return lua_logger_warnx(L);
}

static int
lua_logger_info(lua_State *L)
{
	return lua_logger_infox(L);
}

static int
lua_logger_message(lua_State *L)
{
	return lua_logger_messagex(L);
}

static int
lua_logger_debug(lua_State *L)
{
	return lua_logger_debugx(L);
}

static inline bool
lua_logger_char_safe(int t, unsigned int esc_type)
{
	if (t & 0x80) {
		if (esc_type & LUA_ESCAPE_8BIT) {
			return false;
		}

		return true;
	}

	if (esc_type & LUA_ESCAPE_UNPRINTABLE) {
		if (!g_ascii_isprint(t) && !g_ascii_isspace(t)) {
			return false;
		}
	}

	if (esc_type & LUA_ESCAPE_NEWLINES) {
		if (t == '\r' || t == '\n') {
			return false;
		}
	}

	return true;
}

/* Could return negative value in case of wrong argument number */
static glong
lua_logger_log_format_str(lua_State *L, int offset, char *logbuf, gsize remain,
					const char *fmt,
					enum lua_logger_escape_type esc_type)
{
	const char *c;
	gsize r;
	int digit;

	char *d = logbuf;
	unsigned int arg_num, cur_arg = 0, arg_max = lua_gettop(L) - offset;

	while (remain > 1 && *fmt) {
		if (*fmt == '%') {
			++fmt;
			c = fmt;
			if (*fmt == 's') {
				++fmt;
				++cur_arg;
			} else {
				arg_num = 0;
				while ((digit = g_ascii_digit_value(*fmt)) >= 0) {
					++fmt;
					arg_num = arg_num * 10 + digit;
					if (arg_num >= 100) {
						/* Avoid ridiculously large numbers */
						fmt = c;
						break;
					}
				}

				if (fmt > c) {
					/* Update the current argument */
					cur_arg = arg_num;
				}
			}

			if (fmt > c) {
				if (cur_arg < 1 || cur_arg > arg_max) {
					*d = 0;
					return -((glong) cur_arg + 1); /* wrong argument number */
				}

				r = lua_logger_out(L, offset + cur_arg, d, remain, esc_type);
				g_assert(r < remain);
				remain -= r;
				d += r;
				continue;
			}

			/* Copy % */
			--fmt;
		}

		*d++ = *fmt++;
		--remain;
	}

	*d = 0;

	return d - logbuf;
}

static gsize
lua_logger_out_str(lua_State *L, int pos,
				   char *outbuf, gsize len,
				   enum lua_logger_escape_type esc_type)
{
	static const char hexdigests[16] = "0123456789abcdef";
	gsize slen;
	const unsigned char *str = lua_tolstring(L, pos, &slen);
	unsigned char c;
	char *out = outbuf;

	if (str) {
		while (slen > 0 && len > 1) {
			c = *str++;
			if (lua_logger_char_safe(c, esc_type)) {
				*out++ = c;
			}
			else if (len > 3) {
				/* Need to escape non-printed characters */
				*out++ = '\\';
				*out++ = hexdigests[c >> 4];
				*out++ = hexdigests[c & 0xF];
				len -= 2;
			}
			else {
				*out++ = '?';
			}
			--slen;
			--len;
		}
	}
	*out = 0;

	return out - outbuf;
}

static gsize
lua_logger_out_num(lua_State *L, int pos, char *outbuf, gsize len)
{
	double num = lua_tonumber(L, pos);
	glong inum = (glong) num;

	if ((double) inum == num) {
		return rspamd_snprintf(outbuf, len, "%l", inum);
	}

	return rspamd_snprintf(outbuf, len, "%f", num);
}

static gsize
lua_logger_out_boolean(lua_State *L, int pos, char *outbuf, gsize len)
{
	gboolean val = lua_toboolean(L, pos);

	return rspamd_snprintf(outbuf, len, val ? "true" : "false");
}

static gsize
lua_logger_out_userdata(lua_State *L, int pos, char *outbuf, gsize len)
{
	gsize r = 0;
	int top;
	const char *str = NULL;
	gboolean converted_to_str = FALSE;

	top = lua_gettop(L);
	if (pos < 0) {
		pos += top + 1; /* Convert to absolute */
	}

	if (!lua_getmetatable(L, pos)) {
		return 0;
	}

	lua_pushstring(L, "__index");
	lua_gettable(L, -2);

	if (!lua_istable(L, -1)) {

		if (lua_isfunction(L, -1)) {
			/* Functional metatable, try to get __tostring directly */
			lua_pushstring(L, "__tostring");
			lua_gettable(L, -3);

			if (lua_isfunction(L, -1)) {
				lua_pushvalue(L, pos);

				if (lua_pcall(L, 1, 1, 0) == 0) {
					str = lua_tostring(L, -1);
					if (str) {
						r = rspamd_snprintf(outbuf, len, "%s", str);
					}
				}
			}
		}
		lua_settop(L, top);

		return r;
	}

	lua_pushstring(L, "__tostring");
	lua_gettable(L, -2);

	if (lua_isfunction(L, -1)) {
		lua_pushvalue(L, pos);

		if (lua_pcall(L, 1, 1, 0) != 0) {
			lua_settop(L, top);

			return 0;
		}

		str = lua_tostring(L, -1);

		if (str) {
			converted_to_str = TRUE;
		}
	}
	else {
		lua_pop(L, 1);
		lua_pushstring(L, "class");
		lua_gettable(L, -2);

		if (lua_isstring(L, -1)) {
			str = lua_tostring(L, -1);
			converted_to_str = TRUE;
		}
	}

	if (converted_to_str) {
		r = rspamd_snprintf(outbuf, len, "%s", str);
	}
	else {
		/* Print raw pointer */
		r = rspamd_snprintf(outbuf, len, "%s(%p)", str, lua_touserdata(L, pos));
	}

	lua_settop(L, top);

	return r;
}

#define MOVE_BUF(d, remain, r)      \
	(d) += (r);                 \
	(remain) -= (r);            \
	if ((remain) <= 1) {        \
		lua_settop(L, top); \
		goto table_oob;     \
	}

static gsize
lua_logger_out_table(lua_State *L, int pos, char *outbuf, gsize len,
					 struct lua_logger_trace *trace,
					 enum lua_logger_escape_type esc_type)
{
	char *d = outbuf, *str;
	gsize remain = len;
	glong r;
	gboolean first = TRUE;
	gconstpointer self = NULL;
	int i, last_seq = 0, top;
	double num;
	glong inum;

	/* Type and length checks are done in logger_out_type() */

	self = lua_topointer(L, pos);

	/* Check if we have seen this pointer */
	for (i = 0; i < TRACE_POINTS; i++) {
		if (trace->traces[i] == self) {
			if ((trace->cur_level + TRACE_POINTS - 1) % TRACE_POINTS == i) {
				return rspamd_snprintf(d, remain, "__self");
			}
			return rspamd_snprintf(d, remain, "ref(%p)", self);
		}
	}

	trace->traces[trace->cur_level % TRACE_POINTS] = self;
	++trace->cur_level;

	top = lua_gettop(L);
	if (pos < 0) {
		pos += top + 1; /* Convert to absolute */
	}

	r = rspamd_snprintf(d, remain, "{");
	MOVE_BUF(d, remain, r);

	/* Get numeric keys (ipairs) */
	for (i = 1;; i++) {
		lua_rawgeti(L, pos, i);

		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			last_seq = i;
			break;
		}

		if (first) {
			first = FALSE;
			str =  "[%d] = ";
		} else {
			str =  ", [%d] = ";
		}
		r = rspamd_snprintf(d, remain, str, i);
		MOVE_BUF(d, remain, r);

		r = lua_logger_out_type(L, -1, d, remain, trace, esc_type);
		MOVE_BUF(d, remain, r);

		lua_pop(L, 1);
	}

	/* Get string keys (pairs) */
	for (lua_pushnil(L); lua_next(L, pos); lua_pop(L, 1)) {
		/* 'key' is at index -2 and 'value' is at index -1 */

		/* Preserve key */
		lua_pushvalue(L, -2);
		if (last_seq > 0) {
			if (lua_type(L, -1) == LUA_TNUMBER) {
				num = lua_tonumber(L, -1); /* no conversion here */
				inum = (glong) num;
				if ((double) inum == num && inum > 0 && inum < last_seq) {
					/* Already seen */
					lua_pop(L, 1);
					continue;
				}
			}
		}

		if (first) {
			first = FALSE;
			str = "[%2] = %1";
		} else {
			str = ", [%2] = %1";
		}
		r = lua_logger_log_format_str(L, top + 1, d, remain, str, esc_type);
		if (r < 0) {
			/* should not happen */
			goto table_oob; 
		}
		MOVE_BUF(d, remain, r);

		/* Remove key */
		lua_pop(L, 1);
	}

	r = rspamd_snprintf(d, remain, "}");
	d += r;

table_oob:
	--trace->cur_level;

	return (d - outbuf);
}

#undef MOVE_BUF

static gsize
lua_logger_out_type(lua_State *L, int pos,
						  char *outbuf, gsize len,
						  struct lua_logger_trace *trace,
						  enum lua_logger_escape_type esc_type)
{
	if (len == 0) {
		return 0;
	}

	int type = lua_type(L, pos);

	switch (type) {
	case LUA_TNUMBER:
		return lua_logger_out_num(L, pos, outbuf, len);
	case LUA_TBOOLEAN:
		return lua_logger_out_boolean(L, pos, outbuf, len);
	case LUA_TTABLE:
		return lua_logger_out_table(L, pos, outbuf, len, trace, esc_type);
	case LUA_TUSERDATA:
		return lua_logger_out_userdata(L, pos, outbuf, len);
	case LUA_TFUNCTION:
		return rspamd_snprintf(outbuf, len, "function");
	case LUA_TLIGHTUSERDATA:
		return rspamd_snprintf(outbuf, len, "0x%p", lua_topointer(L, pos));
	case LUA_TNIL:
		return rspamd_snprintf(outbuf, len, "nil");
	case LUA_TNONE:
		return rspamd_snprintf(outbuf, len, "no value");
	}

	/* Try to push everything as string using tostring magic */
	return lua_logger_out_str(L, pos, outbuf, len, esc_type);
}

gsize lua_logger_out(lua_State *L, int pos,
						  char *outbuf, gsize len,
						  enum lua_logger_escape_type esc_type)
{
	struct lua_logger_trace tr;
	memset(&tr, 0, sizeof(tr));

	return lua_logger_out_type(L, pos, outbuf, len, &tr, esc_type);
}

static const char *
lua_logger_get_id(lua_State *L, int pos, GError **err)
{
	const char *uid = NULL, *clsname;

	if (lua_getmetatable(L, pos) != 0) {
		uid = "";
		lua_pushstring(L, "__index");
		lua_gettable(L, -2);

		lua_pushstring(L, "class");
		lua_gettable(L, -2);

		clsname = lua_tostring(L, -1);

		if (strcmp(clsname, rspamd_task_classname) == 0) {
			struct rspamd_task *task = lua_check_task(L, pos);

			if (task) {
				uid = task->task_pool->tag.uid;
			}
			else {
				g_set_error(err, g_quark_from_static_string("lua_logger"),
							EINVAL, "invalid rspamd{task}");
			}
		}
		else if (strcmp(clsname, rspamd_mempool_classname) == 0) {
			rspamd_mempool_t *pool;

			pool = rspamd_lua_check_mempool(L, pos);

			if (pool) {
				uid = pool->tag.uid;
			}
			else {
				g_set_error(err, g_quark_from_static_string("lua_logger"),
							EINVAL, "invalid rspamd{mempool}");
			}
		}
		else if (strcmp(clsname, rspamd_config_classname) == 0) {
			struct rspamd_config *cfg;

			cfg = lua_check_config(L, pos);

			if (cfg) {
				if (cfg->checksum) {
					uid = cfg->checksum;
				}
			}
			else {
				g_set_error(err, g_quark_from_static_string("lua_logger"),
							EINVAL, "invalid rspamd{config}");
			}
		}
		else if (strcmp(clsname, rspamd_map_classname) == 0) {
			struct rspamd_lua_map *map;

			map = lua_check_map(L, pos);

			if (map) {
				if (map->map) {
					uid = map->map->tag;
				}
				else {
					uid = "embedded";
				}
			}
			else {
				g_set_error(err, g_quark_from_static_string("lua_logger"),
							EINVAL, "invalid rspamd{map}");
			}
		}
		else {
			g_set_error(err, g_quark_from_static_string("lua_logger"),
						EINVAL, "unknown class: %s", clsname);
		}


		/* Metatable, __index, classname */
		lua_pop(L, 3);
	}
	else {
		g_set_error(err, g_quark_from_static_string("lua_logger"),
					EINVAL, "no metatable found for userdata");
	}

	return uid;
}

static gboolean
lua_logger_log_format(lua_State *L, int fmt_pos, gboolean is_string,
					  char *logbuf, gsize remain)
{
	const char *fmt = lua_tostring(L, fmt_pos);
	if (fmt == NULL) {
		return FALSE;
	}

	glong ret = lua_logger_log_format_str(L, fmt_pos, logbuf, remain, fmt, is_string ? LUA_ESCAPE_UNPRINTABLE : LUA_ESCAPE_LOG);
	if (ret < 0) {
		msg_err("wrong argument number: %ud", -((int) ret + 1));
		return FALSE;
	}
	return TRUE;
}

static int
lua_logger_do_log(lua_State *L,
				  GLogLevelFlags level,
				  gboolean is_string,
				  int start_pos)
{
	char logbuf[RSPAMD_LOGBUF_SIZE - 128];
	const char *uid = NULL;
	int ret;

	if (lua_type(L, start_pos) == LUA_TUSERDATA) {
		GError *err = NULL;

		uid = lua_logger_get_id(L, start_pos, &err);

		if (uid == NULL) {
			ret = luaL_error(L, "bad userdata for logging: %s",
							 err ? err->message : "unknown error");

			if (err) {
				g_error_free(err);
			}

			return ret;
		}

		++start_pos;
	}

	if (lua_type(L, start_pos) != LUA_TSTRING) {
		/* Bad argument type */
		return luaL_error(L, "bad format string type: %s",
						  lua_typename(L, lua_type(L, start_pos)));
	}

	ret = lua_logger_log_format(L, start_pos, is_string, logbuf, sizeof(logbuf));

	if (ret) {
		if (is_string) {
			lua_pushstring(L, logbuf);
			return 1;
		}
		else {
			lua_common_log_line(level, L, logbuf, uid, "lua", 1);
		}
	}
	else if (is_string) {
		lua_pushnil(L);
		return 1;
	}

	return 0;
}

static int
lua_logger_errx(lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log(L, G_LOG_LEVEL_CRITICAL, FALSE, 1);
}

static int
lua_logger_warnx(lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log(L, G_LOG_LEVEL_WARNING, FALSE, 1);
}

static int
lua_logger_infox(lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log(L, G_LOG_LEVEL_INFO, FALSE, 1);
}

static int
lua_logger_messagex(lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log(L, G_LOG_LEVEL_MESSAGE, FALSE, 1);
}

static int
lua_logger_debugx(lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log(L, G_LOG_LEVEL_DEBUG, FALSE, 1);
}

static int
lua_logger_logx(lua_State *L)
{
	LUA_TRACE_POINT;
	GLogLevelFlags flags = lua_tonumber(L, 1);
	const char *modname = lua_tostring(L, 2), *uid = NULL;
	char logbuf[RSPAMD_LOGBUF_SIZE - 128];
	gboolean ret;
	int stack_pos = 1;

	if (lua_type(L, 3) == LUA_TSTRING) {
		uid = luaL_checkstring(L, 3);
	}
	else if (lua_type(L, 3) == LUA_TUSERDATA) {
		uid = lua_logger_get_id(L, 3, NULL);
	}
	else {
		uid = "???";
	}

	if (uid && modname) {
		if (lua_type(L, 4) == LUA_TSTRING) {
			ret = lua_logger_log_format(L, 4, FALSE, logbuf, sizeof(logbuf));
		}
		else if (lua_type(L, 4) == LUA_TNUMBER) {
			stack_pos = lua_tonumber(L, 4);
			ret = lua_logger_log_format(L, 5, FALSE, logbuf, sizeof(logbuf));
		}
		else {
			return luaL_error(L, "invalid argument on pos 4");
		}

		if (ret) {
			lua_common_log_line(flags, L, logbuf, uid, modname, stack_pos);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 0;
}


static int
lua_logger_debugm(lua_State *L)
{
	LUA_TRACE_POINT;
	char logbuf[RSPAMD_LOGBUF_SIZE - 128];
	const char *uid = NULL, *module = NULL;
	int stack_pos = 1;
	gboolean ret;

	module = luaL_checkstring(L, 1);

	if (lua_type(L, 2) == LUA_TSTRING) {
		uid = luaL_checkstring(L, 2);
	}
	else {
		uid = lua_logger_get_id(L, 2, NULL);
	}

	if (uid && module) {
		if (lua_type(L, 3) == LUA_TSTRING) {
			ret = lua_logger_log_format(L, 3, FALSE, logbuf, sizeof(logbuf));
		}
		else if (lua_type(L, 3) == LUA_TNUMBER) {
			stack_pos = lua_tonumber(L, 3);
			ret = lua_logger_log_format(L, 4, FALSE, logbuf, sizeof(logbuf));
		}
		else {
			return luaL_error(L, "invalid argument on pos 3");
		}

		if (ret) {
			lua_common_log_line(G_LOG_LEVEL_DEBUG, L, logbuf, uid, module, stack_pos);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 0;
}


static int
lua_logger_slog(lua_State *L)
{
	return lua_logger_do_log(L, 0, TRUE, 1);
}

static int
lua_logger_log_level(lua_State *L)
{
	int log_level = rspamd_log_get_log_level(NULL);

	lua_pushstring(L, rspamd_get_log_severity_string(log_level));

	return 1;
}

/*** Init functions ***/

static int
lua_load_logger(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, loggerlib_f);

	return 1;
}

void luaopen_logger(lua_State *L)
{
	rspamd_lua_add_preload(L, "rspamd_logger", lua_load_logger);
}
