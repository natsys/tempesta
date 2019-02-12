/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_CFG_H__
#define __TFW_CFG_H__

#include <linux/list.h>

/*
 * ------------------------------------------------------------------------
 *	Interface for Tempesta FW modules.
 * ------------------------------------------------------------------------
 */

#define TFW_CFG_PATH "/etc/tempesta/tempesta_fw.conf"

/*
 * For simplicity, attributes and values are stored in a static array.
 * At this point we can't handle unlimited number of values like this:
 *   listen :8081 :8082 :8083 :8084 :8085 :8086 :8087 :8088 :8089 8090;
 *
 * Currently there's the maximum of 16 values and 16 attributes per entry.
 *
 * Also, long lists of values looks ugly, so almost always you would want
 * to transform the example above to something like this:
 *   listen 8081;
 *   listen 8082;
 *   listen 8083;
 * ...which is feasible with the current implementation.
 */
#define TFW_CFG_ENTRY_VAL_MAX  16
#define TFW_CFG_ENTRY_ATTR_MAX 16

#define TFW_CFG_RULE_NAME	"rule"

/**
 * TfwCfgEntry represents a single parsed entry in a configuration file.
 *
 * Consider this raw configuration example:
 *     server example.com {
 *         listen 10.0.0.1:80 192.168.0.1:80 :8080 proto=http;
 *         listen :443 [::0]:443 proto=https;
 *     }
 * This is not a real configuration, but it is synthetically correct.
 * If it's parsed, the parser would produce the following three entries:
 *  1. TfwCfgEntry {
 *         .name = "server",
 *         .val_n = 1,
 *         .vals = { "example.com" }
 *         .have_children = true
 *     }
 *  2. TfwCfgEntry {
 *         .name = "listen",
 *         .val_n = 3,
 *         .vals = { "10.0.0.1:80", "192.168.0.1:80", ":8080" },
 *         .attr_n = 1,
 *         .attrs = { { .key="proto", .val="http" } },
 *         .have_children = false
 *     }
 *  3. TfwCfgEntry {
 *         .name = "listen",
 *         .val_n = 2,
 *         .vals = { ":443", "[::0]:443" },
 *         .attr_n = 1,
 *         .attrs = { { .key="proto", .val="https" } },
 *         .have_children = false
 *     }
 *
 * Both sections and directives are expressed by TfwCfgEntry{} structure.
 * The difference is in @have_children flag which is true for sections.
 *
 * TfwCfgEntry{} structure also supports an alternative way to specify
 * directives - in form of rules; structure TfwCfgRule{} (and field @rule
 * of TfwCfgEntry{} structure) is responsible for rules parsing. The
 * following rule:
 *                  uri != "static*" -> mark = 1;
 *
 * if parsed, will have following representation in TfwCfgEntry{}:
 *   TfwCfgEntry {
 *         .name = "rule",
 *         ...
 *         .rule = {
 *                   .fst = "uri",
 *                   .snd = "static*",
 *                   .act = "mark",
 *                   .val = "1",
 *                   .inv = true
 *                 },
 *         ...
 *   }
 *
 * In above example @inv field of TfwCfgRule{} structure is responsible for
 * comparison sign interpretation in rule condition part:
 *                     "==" => false / "!=" => true
 *
 * Also extended rule form is used in case of specifying HTTP headers. Following
 * rule:
 *               hdr "Referer" == "*example.com" -> mark = 7;
 *
 * will have following representation:
 *   TfwCfgEntry {
 *         .name = "rule",
 *         ...
 *         .rule = {
 *                   .fst	= "hdr",
 *                   .fst_ext	= "Referer",
 *                   .snd	= "*example.com",
 *                   .act	= "mark",
 *                   .val	= "7",
 *                   .inv	= false
 *                 },
 *         ...
 *   }
 *
 * @ftoken is an auxiliary internal field of TfwCfgEntry{} structure which
 * helps parser to differentiate plain directives from rules.
 *
 * TfwCfgEntry{} is a temporary structure that lives only during the parsing
 * and acts as an interface between the parser FSM and TfwCfgSpec{}->handler.
 * The parser accumulates data in a TfwCfgEntry{} instance. When the
 * current entry is complete, the parser executes the handler and then
 * destroys the instance.
 *
 * These two members help to show a proper parsing error to a user:
 * @line_no	- Current line number in the configuration file.
 * @line	- Pointer to the start of the current line.
 */
typedef struct {
	const char *fst;
	const char *fst_ext;
	const char *snd;
	const char *act;
	const char *val;
	bool inv;
} TfwCfgRule;

typedef struct {
	struct {
		bool have_children : 1;
		bool dflt_value : 1;
	};
	size_t val_n;
	size_t attr_n;
	const char *name;
	const char *vals[TFW_CFG_ENTRY_VAL_MAX];
	struct {
		const char *key;
		const char *val;
	} attrs[TFW_CFG_ENTRY_ATTR_MAX];
	TfwCfgRule rule;
	const char *ftoken;
	size_t line_no;
	const char *line;
} TfwCfgEntry;

/**
 * Usage example:
 *   int print_attrs(const TfwCfgEntry *entry)
 *   {
 *           const char *key, *val;
 *           int i;
 *           TFW_CFG_ENTRY_FOR_EACH_ATTR(entry, i, key, val) {
 *                   printk("%s = %s\n", key, val);
 *           }
 *   }
 */
#define TFW_CFG_ENTRY_FOR_EACH_ATTR(e, idx, k, v)	\
	for ((idx) = 0, (k) = (e)->attrs[0].key, (v) = (e)->attrs[0].val; \
	     (idx++) < (e)->attr_n; \
	     (k) = (e)->attrs[(idx)].key, (v) = (e)->attrs[(idx)].val)

#define TFW_CFG_ENTRY_FOR_EACH_VAL(e, idx, v)	\
	for ((idx) = 0, (v) = (e)->vals[0];	\
	     (idx) < (e)->val_n;		\
	     (v) = (e)->vals[++(idx)])

/**
 * TfwCfgSpec{} is a single instruction for the configuration parser.
 * It specifies a @handler which is executed when the parser meets
 * an entry with given @name.
 *
 * @name is the name of a configuration directive. It is the key for
 * matching with TfwCfgEntry{}->name that is constructed from a string
 * in the configuration file. Typically, an array of TfwCfgSpec{}
 * structures is provided to the parser, and the parser searches for
 * a matching specification for every parsed configuration directive.
 *
 * @deflt is a default value which is used when the configuration file
 * contains no matching directives. In that case the field is parsed
 * into a fake TfwCfgEntry{} object and pushed to @handler in the same
 * way as if it were a part of a real configuration file. That's awkward
 * for simple data types like integers or booleans, but beneficial for
 * complex values like IP addresses and strings where handler functions
 * allocate memory.
 *
 * @handler is a callback function which is responsible for:
 *  1. Serializing strings into native data types.
 *     The parser is not bloated by handling all sorts of data types.
 *     Instead, it does only basic syntax parsing and leaves the rest
 *     to @handler. You may choose an appropriate handler function that
 *     converts a string to a desired type (int, bool, TfwAddr, etc).
 *     Alternatively, you may implement your own handler function
 *     without augmenting the parser, so this is flexible.
 *  2. Copying strings from TfwCfgEntry to some storage.
 *     The TfwCfgEntry{} instance is destroyed after @handler returns.
 *     You can't just save pointers, you need to copy strings located
 *     in the entry. Usually these strings are not needed after they
 *     are parsed, or you can store them in a more efficient way.
 *     That's an easy and simple alternative to reference counters.
 *
 * @dest and @spec_ext are "arguments" used by @handler. Each handler
 * function has its own types of these arguments. Typically, @dest is
 * a destination object which is modified by @handler, and @spec_ext
 * is a spec extension like TfwCfgSpecInt, TfwCfgSpecStr, etc. that
 * describes some constraints like minimum/maximum values.
 * BEWARE: there's no type checking. You need to check carefully that
 * these fields are what @handler expects, or you get a memory corruption.
 *
 * @cleanup is another callback the purpose of which is to free memory
 * allocated by @handler. It is called when the configuration is unloaded
 * (the system is stopped, or an error occurred). The callback is invoked
 * when @handler was called at least once regardless of the handler's
 * return value.
 *
 * @allow_repeat allows to set a restriction on the number of times
 * a directive @name can be seen in the configuration files. If it's
 * set to 'true', then the directive can be specified multiple times.
 * Otherwise, it can be specified just once. Note that the scope of
 * the restriction is the current set of TfwCfgSpec{} definitions.
 * That's either a nested set of definitions, a top-level set of
 * definitions.
 *
 * @allow_none allows to request a mandatory presence of a directive.
 * If it's set to 'false', then the presence of a directive is mandatory.
 * This is the default behavior. Otherwise, a directive can be omitted
 * in the configuration. Again, the scope of the restriction is the
 * current set of TfwCfgSpec{} definitions.
 *
 * @allow_reconfig allows a live reconfiguration of a directive when
 * Tempesta is running already. @handler for the directive must know
 * how to handle a live reconfiguration.
 * NOTE: This is an interim solution. Every configuration directive
 * should have a corresponding handler function that can handle a live
 * reconfiguration. At least to a degree where it's able to report that
 * the value of that directive has changed, but a live reconfiguration
 * is not supported for the directive.
 * NOTE: Enabling @allow_reconfig for a directive requires enabling
 * @allow_reconfig for a parent directive if applied.
 *
 * @__called_now is an internal field. It's set when @handler is invoked
 * during the parsing process that is controlled by current set (array)
 * of TfwCfgSpec{} entries. It's used by the parser to determine whether
 * it needs to process the @deflt field. Also, it's used by the parser
 * to handle restrictions set by @allow_repeat and @allow_none members.
 * @__called_now field is reset when the control of parsing is switched
 * to a nested set of TfwCfgSpec{} entries. Typically, a nested set of
 * TfwCfgSpec{} entries represents a grouping of some sort, and these
 * groups may be repeated multiple times in the configuration file.
 * @__called_now is reset each time that group is parsed.
 *
 * @__called_cfg is also an internal field. It's also set when @handler
 * is invoked during the parsing process. However, it's not reset until
 * the parsing is completed and Tempesta is (re)started. Before it is
 * reset, its state migrates to a corresponding @__called_ever field.
 * If an error occurs before that, it's used to determine whether to
 * invoke a corresponding @cleanup callback.
 *
 * @__called_ever is another internal field. It tracks the state of a
 * corresponding @__called_cfg field after the configuration has been
 * processed and Tempesta successfully (re)started, but not before that.
 * It's never reset until Tempesta is completely stopped. It is used to
 * determine whether to invoke a corresponding @cleanup callback.
 *
 * It's been mentioned that a configuration specification may have nested
 * sets of entries (children). In that case @handler must be set to point
 * to @tfw_cfg_handle_children() function, @dest - to a null-terminated
 * array of nested specs, and @spec_ext must point to an instance of
 * TfwCfgSpecChild{} struct. @cleanup function that cleans up the results
 * of parsing of a specific parent specification and its nested entries
 * is mandatory in this case. Generic @tfw_cfg_cleanup_children() function
 * calls @cleanup functions for all nested entries and may be used here.
 * Otherwise, a user-defined function may be provided. In that case it
 * takes responsibility for cleaning up of all nested entries and the
 * parent entry.
 */
typedef struct TfwCfgSpec TfwCfgSpec;
struct TfwCfgSpec {
	const char *name;
	const char *deflt;
	int (*handler)(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
	void *dest;
	void *spec_ext;
	struct {
		bool allow_none:1;
		bool allow_repeat:1;
		bool allow_reconfig:1;
		bool __called_now:1;
		bool __called_cfg:1;
		bool __called_ever:1;
	};
	void (*cleanup)(TfwCfgSpec *self);
};

/**
 * Walks over a NULL-terminated array of TfwCfgSpec structures.
 */
#define TFW_CFG_FOR_EACH_SPEC(spec_pos, spec_arr) \
	for ((spec_pos) = (spec_arr); (spec_pos)->name; ++(spec_pos))

/*
 * ------------------------------------------------------------------------
 *	Generic TfwCfgSpec->handler functions.
 * ------------------------------------------------------------------------
 */

typedef struct {
	const char *name;
	int value;
} TfwCfgEnum;

/* TfwCfgSpec->spec_ext for tfw_cfg_set_int(). */
typedef struct {
	int multiple_of;
	struct {
		long min;
		long max;
	} range;
	TfwCfgEnum *enums;   /* NULL-terminated array. */
} TfwCfgSpecInt;

/**
 * TfwCfgSpec->spec_ext for tfw_cfg_set_str().
 *
 * @len_range is the min/max length constraint for the input string.
 * Ignored when @len_range.min == @len_range.max.
 */
typedef struct {
	struct {
		size_t min;
		size_t max;
	} len_range;
	const char *cset;
} TfwCfgSpecStr;

/**
 * TfwCfgSpec->spec_ext for tfw_cfg_handle_children().
 *
 * The @begin_hook is called before any children are parsed.
 * The @finish_hook is called after all children entries are parsed.
 */
typedef struct {
	int (*begin_hook)(TfwCfgSpec *self, TfwCfgEntry *parent_entry);
	int (*finish_hook)(TfwCfgSpec *self);
} TfwCfgSpecChild;

static inline bool
tfw_cfg_is_dflt_value(TfwCfgEntry *cfg_entry)
{
	return cfg_entry->dflt_value;
}

/*
 * Tempesta strives to support live reconfiguration. New configuration
 * is loaded, processed and set while Tempesta is running. Ultimately,
 * directives in configuration file are translated into internal data
 * structures in Tempesta. Internal data structures for data that may
 * be reconfigured need to have a configuration flags member that will
 * indicate one of several major actions noted below. Implementation
 * of each action is specific to configuration entry.
 * NOTE: In server.h there are also flags definitions for the same field;
 * those flags control the server's health monitor functionality.
 */
enum {
	TFW_CFG_B_ADD = 0,	/* Add an entry */
	TFW_CFG_B_DEL,		/* Delete an entry */
	TFW_CFG_B_MOD,		/* Modify an entry */
	TFW_CFG_B_KEEP,		/* Keep an entry */
};

#define TFW_CFG_F_ADD		(1 << TFW_CFG_B_ADD)
#define TFW_CFG_F_DEL		(1 << TFW_CFG_B_DEL)
#define TFW_CFG_F_MOD		(1 << TFW_CFG_B_MOD)
#define TFW_CFG_F_KEEP		(1 << TFW_CFG_B_KEEP)
#define TFW_CFG_M_ACTION	\
	(TFW_CFG_F_ADD | TFW_CFG_F_DEL | TFW_CFG_F_MOD | TFW_CFG_F_KEEP)

/* Generic TfwCfgSpec->handler functions. */
int tfw_cfg_set_bool(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_int(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_long(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_str(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_handle_children(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
void tfw_cfg_cleanup_children(TfwCfgSpec *cs);

/* Various helpers for building custom handler functions. */
int tfw_cfg_check_range(long value, long min, long max);
int tfw_cfg_check_multiple_of(long value, int divisor);
int tfw_cfg_check_val_n(const TfwCfgEntry *e, int val_n);
int tfw_cfg_check_single_val(const TfwCfgEntry *e);
int __tfw_cfg_parse_int(const char *s, int *out_int);
int tfw_cfg_parse_int(const char *s, int *out_int);
int tfw_cfg_parse_uint(const char *s, unsigned int *out_uint);
int tfw_cfg_parse_long(const char *s, long *out_long);
int tfw_cfg_parse_intvl(const char *s, unsigned long *i0, unsigned long *i1);
int tfw_cfg_map_enum(const TfwCfgEnum mappings[],
		     const char *in_name, void *out_int);
const char *tfw_cfg_get_attr(const TfwCfgEntry *e, const char *attr_key,
			     const char *default_val);

/* Functions for making dynamic additions to configuration. */
TfwCfgSpec *tfw_cfg_spec_find(TfwCfgSpec specs[], const char *name);
int tfw_cfg_parse_mods(const char *cfg_text, struct list_head *mod_list);

void *tfw_cfg_read_file(const char *path, size_t *file_size);

int tfw_cfg_parse(struct list_head *mod_list);
void tfw_cfg_cleanup(struct list_head *mod_list);
void tfw_cfg_conclude(struct list_head *mod_list);

#endif /* __TFW_CFG_H__ */
