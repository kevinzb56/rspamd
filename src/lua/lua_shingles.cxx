/*
 * Copyright 2025 Vsevolod Stakhov
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
#include "lua_classnames.h"
#include "shingles.h"
#include "contrib/fmt/include/fmt/format.h"
#include <set>

/***
 * @module rspamd_shingle
 * This module provides methods to work with text shingles, including multiclass classification support.
 */

/***
 * @method shingle:to_table()
 * Converts shingle to table of decimal strings
 * @return {table} table of RSPAMD_SHINGLE_SIZE decimal strings
 */
LUA_FUNCTION_DEF(shingle, to_table);

/***
 * @method shingle:get(index)
 * Gets element at index as two lua_Integer values (high and low 32 bits)
 * @param {number} index 1-based index
 * @return {number,number} high and low 32-bit parts
 */
LUA_FUNCTION_DEF(shingle, get);

/***
 * @method shingle:get_string(index)
 * Gets element at index as decimal string
 * @param {number} index 1-based index
 * @return {string} decimal representation
 */
LUA_FUNCTION_DEF(shingle, get_string);

/***
 * @method shingle:get_class_hashes(category)
 * Gets all shingle hashes for a specific category
 * @param {string} category Category name (e.g., "spam", "finance")
 * @return {table} Table of shingle hashes belonging to that category
 */
LUA_FUNCTION_DEF(shingle, get_class_hashes);

/***
 * @method shingle:get_all_classes()
 * Returns a list of all available categories in the shingle
 * @return {table} Table containing category names
 */
LUA_FUNCTION_DEF(shingle, get_all_classes);

static const struct luaL_reg shinglelib_m[] = {
    LUA_INTERFACE_DEF(shingle, to_table),
    LUA_INTERFACE_DEF(shingle, get),
    LUA_INTERFACE_DEF(shingle, get_string),
    LUA_INTERFACE_DEF(shingle, get_all_classes),
    LUA_INTERFACE_DEF(shingle, get_class_hashes),
    {"__tostring", rspamd_lua_class_tostring},
    {nullptr, nullptr}
};

static struct rspamd_shingle *
lua_check_shingle(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_shingle_classname);
	luaL_argcheck(L, ud != nullptr, pos, "'shingle' expected");
	return static_cast<struct rspamd_shingle *>(ud);
}

void lua_newshingle(lua_State *L, const void *sh)
{
	auto *nsh = static_cast<struct rspamd_shingle *>(
		lua_newuserdata(L, sizeof(struct rspamd_shingle)));

    if (sh != nullptr) {
        memcpy(nsh, sh, sizeof(struct rspamd_shingle));
    }
    else {
        memset(nsh->hashes, 0, sizeof(nsh->hashes));
        memset(nsh->categories, 0, sizeof(nsh->categories));
    }

	rspamd_lua_setclass(L, rspamd_shingle_classname, -1);
}

static int
lua_shingle_to_table(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *sh = lua_check_shingle(L, 1);

	lua_createtable(L, RSPAMD_SHINGLE_SIZE, 0);

	for (int i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
		auto str = fmt::format("{}", sh->hashes[i]);
		lua_pushstring(L, str.c_str());
		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}

static int
lua_shingle_get(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *sh = lua_check_shingle(L, 1);
	auto idx = luaL_checkinteger(L, 2) - 1;

	if (idx < 0 || idx >= RSPAMD_SHINGLE_SIZE) {
		return luaL_error(L, "index out of bounds: %d", idx + 1);
	}

	uint64_t val = sh->hashes[idx];
	lua_pushinteger(L, (lua_Integer) (val >> 32));
	lua_pushinteger(L, (lua_Integer) (val & 0xFFFFFFFF));

	return 2;
}

static int
lua_shingle_get_string(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *sh = lua_check_shingle(L, 1);
	auto idx = luaL_checkinteger(L, 2) - 1;

	if (idx < 0 || idx >= RSPAMD_SHINGLE_SIZE) {
		return luaL_error(L, "index out of bounds: %d", idx + 1);
	}

	auto str = fmt::format("{}", sh->hashes[idx]);
	lua_pushstring(L, str.c_str());

	return 1;
}

static int
lua_shingle_get_class_hashes(lua_State *L)
{
    LUA_TRACE_POINT;
    auto *sh = lua_check_shingle(L, 1);
    const char *category = luaL_checkstring(L, 2);

    lua_createtable(L, 0, 0);
    int index = 1;

    for (int i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
        if (sh->categories[i] && strcmp(sh->categories[i], category) == 0) {
            auto str = fmt::format("{}", sh->hashes[i]);
            lua_pushstring(L, str.c_str());
            lua_rawseti(L, -2, index++);
        }
    }

    return 1;
}

static int
lua_shingle_get_all_classes(lua_State *L)
{
    LUA_TRACE_POINT;
    auto *sh = lua_check_shingle(L, 1);

    lua_createtable(L, 0, 0);
    std::set<std::string> unique_classes;

    for (int i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
        if (sh->categories[i]) {
            unique_classes.insert(sh->categories[i]);
        }
    }

    int index = 1;
    for (const auto &cat : unique_classes) {
        lua_pushstring(L, cat.c_str());
        lua_rawseti(L, -2, index++);
    }

    return 1;
}

void
luaopen_shingle(lua_State *L)
{
	rspamd_lua_new_class(L, rspamd_shingle_classname, shinglelib_m);
	lua_pop(L, 1);
}