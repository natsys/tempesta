/**
 *		Tempesta FW
 *
 * Tempesta FW Configuration Framework.
 *
 * Requirements:
 *  - The configuring process must be habitual for any system administrator.
 *  - An ability to specify relatively complex configuration entities
 *    (lists, dictionaries, trees, etc).
 *  - Decomposition into modules. Other Tempesta subsystems should be able to
 *    register their sections in a configuration file. That should be possible
 *    for other kernel modules as well, so late binding has to be used.
 *  - Configuration refresh in run time (at least partially).
 *  - An ability to manage very large lists (e.g. blocked IP addresses).
 *
 *  None of existing approaches (sysfs, configfs, sysctl, ioctl) mets all the
 *  requirements, so we implement our own configuration subsystem. Current
 *  implementation doesn't fit all requirements either, but it is flexible
 *  enough for future extensions.
 *
 *  Basically, we store configuration in plain-text files and read them via VFS
 *  and parse right in the kernel space. This is not very conventional, but
 *  allows to pass relatively complex data structures to the kernel.
 *
 *  The configuration looks like this:
 *    entry1 42;
 *    entry2 1 2 3 foo=bar;
 *    entry3 {
 *        sub_entry1;
 *        sub_entry2;
 *    }
 *    entry4 with_value {
 *       and_subentries {
 *           and_subsubentries;
 *       }
 *    }
 *  It consists of entries. Each entry has:
 *    1. name;
 *    2. values (usually just one, but variable number of values is supported);
 *    3. attributes (a dictionary of key-value pairs);
 *    4. children entries (such entries act as sections or trees);
 *  The only name is required. Everything else is optional. The idea is similar
 *  to SDL (http://www.ikayzo.org/display/SDL/Language+Guide), but our syntax
 *  and terminology is more habitual for C/Linux programmers and users.
 *
 *  Tempesta FW modules register themselves and provide configuration specs
 *  via TfwMod{} and TfwCfgSpec{} structures. The code here pushes events
 *  and parsed configuration via callbacks specified in these structures.
 *
 *  The code in this unit contains four main entities:
 *    1. The configuration parser.
 *       We utilize FSM approach for the parser. The code is divided into two
 *       FSMs: TFSM (tokenizer) and PFSM (the parser that produces entries).
 *    2. A bunch of generic  TfwCfgSpec->handler callbacks for the parser.
 *    3. TfwMod{} list related routines, the top-level parsing routine.
 *       This part of code implements publishing start/stop events and parsed
 *       configuration data across modules.
 *    4. The list of registered modules, VFS and sysctl helpers, kernel module
 *       parameters. The stateful part of code.
 *
 * TODO:
 *  - "include" directives.
 *  - Handling large sets of data, possibly via TDB.
 *  - Improve efficiency: too many memory allocations and data copying.
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

#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#if DBG_CFG == 0
#undef DEBUG
#endif
#include "addr.h"
#include "cfg.h"
#include "client.h"
#include "log.h"

/*
 * ------------------------------------------------------------------------
 *	Configuration Parser - TfwCfgEntry helpers
 * ------------------------------------------------------------------------
 *
 * TfwCfgEntry is a temporary structure that servers only as an interface
 * between the parser and TfwCfgSpec->handler callbacks.
 * The parser walks over input entries accumulating data in the TfwCfgEntry
 * structure. As soon as an entry is parsed, the parser invokes the handler
 * callback and then destroys the TfwCfgEntry object.
 *
 * Strings in the TfwCfgEntry are pieces of the input plain-text configuration,
 * but they have to be NULL-terminated, so we have to allocate space and copy
 * them. Helpers below facilitate that.
 */

static const char *
__alloc_and_copy_literal(const char *src, size_t len, bool keep_bs)
{
	const char *src_pos, *src_end;
	char *dst, *dst_pos;
	bool is_escaped;

	BUG_ON(!src);

	dst = kmalloc(len + 1, GFP_KERNEL);
	if (!dst) {
		TFW_ERR_NL("can't allocate memory\n");
		return NULL;
	}

	/* Copy the string. Eat escaping backslashes if @keep_bs is not set. */
	/* FIXME: the logic looks like a tiny FSM,
	 *        so perhaps it should be included to the TFSM. */
	src_end = src + len;
	src_pos = src;
	dst_pos = dst;
	is_escaped = false;
	while (src_pos < src_end) {
		if (*src_pos != '\\' || is_escaped || keep_bs) {
			is_escaped = false;
			*dst_pos = *src_pos;
			++dst_pos;
		}
		else if (*src_pos == '\\') {
			is_escaped = true;
		}
		++src_pos;
	}
	*dst_pos = '\0';

	return dst;
}

static inline const char *
alloc_and_copy_literal(const char *src, size_t len)
{
	return __alloc_and_copy_literal(src, len, false);
}

static inline const char *
alloc_and_copy_literal_bs(const char *src, size_t len)
{
	return __alloc_and_copy_literal(src, len, true);
}

/**
 * Check name of an attribute or name
 *
 * Much like C identifiers, names must start with a letter and consist
 * only of alphanumeric and underscore characters. Currently this is
 * only a sanity check and the parser code would work without it, but in
 * future it may help to preserve compatibility if we decide to change
 * the parser.
 */
static bool
check_identifier(const char *buf, size_t len)
{
	size_t i;

	if (!len) {
		TFW_ERR_NL("the string is empty\n");
		return false;
	}

	if ((len == 1) && (buf[0] == '*'))
		return true;

	if (!isalpha(buf[0])) {
		TFW_ERR_NL("the first character is not a letter: '%c'\n",
			   buf[0]);
		return false;
	}

	for (i = 0; i < len; ++i) {
		if (!isalnum(buf[i]) && buf[i] != '_') {
			TFW_ERR_NL("invalid character: '%c' in '%.*s'\n",
				   buf[i], (int)len, buf);
			return false;
		}
	}

	return true;
}

static inline void
rule_reset(TfwCfgRule *rule)
{
	kfree(rule->fst);
	kfree(rule->fst_ext);
	kfree(rule->snd);
	kfree(rule->act);
	kfree(rule->val);
}

static void
entry_reset(TfwCfgEntry *e)
{
	const char *key, *val;
	size_t i;

	BUG_ON(!e);

	kfree(e->name);
	kfree(e->ftoken);

	TFW_CFG_ENTRY_FOR_EACH_VAL(e, i, val)
		kfree(val);

	TFW_CFG_ENTRY_FOR_EACH_ATTR(e, i, key, val) {
		kfree(key);
		kfree(val);
	}

	rule_reset(&e->rule);

	memset(e, 0, sizeof(*e));
}

static int
entry_set_name(TfwCfgEntry *e)
{
	int len;
	const char *name;
	bool rule = !e->ftoken;

	BUG_ON(!e);
	BUG_ON(e->name);

	if (!rule) {
		name = e->ftoken;
		len = strlen(e->ftoken);
	} else {
		name = TFW_CFG_RULE_NAME;
		len = sizeof(TFW_CFG_RULE_NAME) - 1;
	}

	TFW_DBG3("set name: %.*s\n", len, name);

	if (!check_identifier(name, len))
		return -EINVAL;

	if (!rule) {
		e->name = e->ftoken;
		e->ftoken = NULL;
		return 0;
	}

	if (!(e->name = alloc_and_copy_literal(name, len)))
		return -ENOMEM;

	return 0;
}

static int
entry_set_first_token(TfwCfgEntry *e, const char *src, int len)
{
	BUG_ON(!e);
	BUG_ON(e->ftoken);

	TFW_DBG3("set first token: %.*s\n", len, src);

	if (!src || !len)
		return -EINVAL;

	e->ftoken = alloc_and_copy_literal(src, len);
	if (!e->ftoken)
		return -ENOMEM;

	return 0;
}

static int
entry_add_val(TfwCfgEntry *e, const char *val_src, size_t val_len)
{
	const char *val;

	BUG_ON(!e);
	BUG_ON(e->val_n > ARRAY_SIZE(e->vals));

	if (!val_src)
		return -EINVAL;

	if (e->val_n == ARRAY_SIZE(e->vals)) {
		TFW_ERR_NL("maximum number of values per entry reached\n");
		return -ENOBUFS;
	}

	/* Store an incoming value even if it's an empty string. */
	if (val_len)
		val = alloc_and_copy_literal(val_src, val_len);
	else
		val = alloc_and_copy_literal("", 0);

	if (!val)
		return -ENOMEM;

	e->vals[e->val_n++] = val;
	return 0;
}

static int
entry_add_attr(TfwCfgEntry *e, const char *key_src, size_t key_len,
		const char *val_src, size_t val_len)
{
	const char *key, *val;

	BUG_ON(!e);
	BUG_ON(e->attr_n > ARRAY_SIZE(e->attrs));

	if (!key_src || !key_len || !val_src || !val_len)
		return -EINVAL;

	if (e->attr_n == ARRAY_SIZE(e->attrs)) {
		TFW_ERR_NL("maximum number of attributes per entry reached\n");
		return -ENOBUFS;
	}

	if (!check_identifier(key_src, key_len))
		return -EINVAL;

	key = alloc_and_copy_literal(key_src, key_len);
	val = alloc_and_copy_literal(val_src, val_len);

	if (!key || !val) {
		kfree(key);
		kfree(val);
		return -ENOMEM;
	}

	e->attrs[e->attr_n].key = key;
	e->attrs[e->attr_n].val = val;
	++e->attr_n;
	return 0;
}

static int
entry_add_rule_param(const char **param, const char *src, size_t len)
{
	const char *dst;

	BUG_ON(!src);
	if (!(dst = alloc_and_copy_literal(src, len)))
		return -ENOMEM;
	*param = dst;
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	Configuration parser - tokenizer and parser FSMs
 * ------------------------------------------------------------------------
 *
 * Basic terms used in this code:
 *   - MOVE - change FSM state and read the next character/token.
 *   - JMP  - change the state without reading anything.
 *   - SKIP - read the next character/token and re-enter the current state.
 *   - TURN - enter a new state (not re-enter the current state).
 *   - COND_JMP/COND_MOVE/COND_SKIP/etc - do it if the given condition is true.
 *   - lexeme - a sequence of characters in the input buffer.
 *   - token - type/class of a lexeme.
 *   - literal - a lexeme that carries a string value. Regular tokens are syntax
 *               elements, they don't have a value and their lexemes are always
 *               special control characters. Literals are not part of the syntax
 *               and they do have a value.
 *
 * Macro ownership:
 *   - FSM_*() - generic macros shared between PFSM and TFSM.
 *   - PFSM_*()/TFSM_*() - macros specific to parser/tokenizer.
 * For example, FSM_STATE() and FSM_JMP() are generic, they do the same thing
 * in both FSMs (a label and a jump to it); but PFSM_MOVE() and TFSM_MOVE() are
 * different, since they read values from different input streams (tokens and
 * characters respectively).
 */

typedef enum {
	TOKEN_NA = 0,
	TOKEN_LBRACE,
	TOKEN_RBRACE,
	TOKEN_EQSIGN,
	TOKEN_DEQSIGN,
	TOKEN_NEQSIGN,
	TOKEN_SEMICOLON,
	TOKEN_LITERAL,
	TOKEN_ARROW,
	_TOKEN_COUNT,
} token_t;

typedef struct {
	const char  *in;      /* The whole input buffer. */
	const char  *pos;     /* Current position in the @in buffer. */

	/* Current FSM state is saved to here. */
	const void  *fsm_s;   /* Pointer to label (GCC extension). */
	const char  *fsm_ss;  /* Label name as string (for debugging). */

	/* Currently/previously processed character. */
	char        c;
	char        prev_c;

	/* Currently/previously processed token.
	 * The language is context-sensitive, so we need to store all these
	 * previous tokens and literals to parse it without peek()'ing. */
	token_t t;
	token_t prev_t;

	/* Literal value (not NULL only when @t == TOKEN_LITERAL). */
	const char *lit;
	const char *prev_lit;

	/* Length of @lit (the @lit is not terminated). */
	int lit_len;
	int prev_lit_len;

	/* Current line. */
	size_t line_no;
	const char *line;

	int  err;  /* The latest error code. */

	/* Currently parsed entry. Accumulates literals as values/attributes.
	 * When current entry is done, a TfwCfgSpec->handler is called and a new
	 * entry is started. */
	TfwCfgEntry e;
} TfwCfgParserState;

/* Macros common for both TFSM and PFSM. */

#define FSM_STATE(name) 		\
	TFW_DBG3("fsm: implicit exit from: %s\n", ps->fsm_ss); \
	BUG();				\
name:					\
	if (ps->fsm_s != &&name) {	\
		TFW_DBG3("fsm turn: %s -> %s\n", ps->fsm_ss, #name); \
		ps->fsm_s = &&name;	\
		ps->fsm_ss = #name;	\
	}

#define FSM_JMP(to_state) goto to_state

#define FSM_COND_JMP(cond, to_state) \
	FSM_COND_LAMBDA(cond, FSM_JMP(to_state))

#define FSM_COND_LAMBDA(cond, ...)	\
do {					\
	if (cond) {			\
		__VA_ARGS__;		\
	}				\
} while (0)				\

/* Macros specific to TFSM. */

#define TFSM_MOVE(to_state)		\
do {					\
	ps->prev_c = ps->c;		\
	ps->c = *(++ps->pos);		\
	TFW_DBG3("tfsm move: '%c' -> '%c'\n", ps->prev_c, ps->c); \
	if (ps->prev_c == '\n') {	\
		++ps->line_no;		\
		ps->line = ps->pos;	\
	}				\
	FSM_JMP(to_state);		\
} while (0)

#define TFSM_MOVE_EXIT(token_type)	\
do {					\
	ps->t = token_type;		\
	TFSM_MOVE(TS_EXIT);		\
} while (0)

#define TFSM_JMP_EXIT(token_type)	\
do {					\
	ps->t = token_type;		\
	FSM_JMP(TS_EXIT);		\
} while (0)

#define TFSM_SKIP() TFSM_MOVE(*ps->fsm_s);

#define TFSM_COND_SKIP(cond) \
	FSM_COND_LAMBDA(cond, TFSM_SKIP())

#define TFSM_COND_MOVE_EXIT(cond, token_type) \
	FSM_COND_LAMBDA(cond, TFSM_MOVE_EXIT(token_type))

#define TFSM_COND_JMP_EXIT(cond, token_type) \
	FSM_COND_LAMBDA(cond, TFSM_JMP_EXIT(token_type))

#define TFSM_COND_MOVE(cond, to_state) \
	FSM_COND_LAMBDA(cond, TFSM_MOVE(to_state))

/* Macros specific to PFSM. */

#define PFSM_MOVE(to_state)					\
do {								\
	read_next_token(ps);					\
	TFW_DBG3("pfsm move: %d (\"%.*s\") -> %d (\"%.*s\")", 	\
		ps->prev_t, ps->prev_lit_len, ps->prev_lit,  	\
		ps->t, ps->lit_len, ps->lit); 			\
	if(!ps->t) {						\
		ps->err = -EINVAL;				\
		FSM_JMP(PS_EXIT);				\
	}							\
	FSM_JMP(to_state);					\
} while (0)

#define PFSM_COND_MOVE(cond, to_state) \
	FSM_COND_LAMBDA(cond, PFSM_MOVE(to_state))

#define PFSM_COND_JMP_EXIT_ERROR(cond)				\
do {								\
	if (cond) {						\
		TFW_DBG3("pfsm: rule error, %d -> %d", ps->prev_t, ps->t); \
		ps->err = -EINVAL;				\
		FSM_JMP(PS_EXIT);				\
	}							\
} while (0)

/**
 * The TFSM (Tokenizer Finite State Machine).
 *
 * Steps over characters in the input stream and classifies them as tokens.
 * Eats whitespace and comments automatically, never produces tokens for them.
 * Accumulates string literals in @ps->lit.
 * Produces one token per call (puts it to @ps->t), shifts current position
 * accordingly. Produces TOKEN_NA on EOF or invalid input.
 */
static void
read_next_token(TfwCfgParserState *ps)
{
	ps->prev_t = ps->t;
	ps->prev_lit = ps->lit;
	ps->prev_lit_len = ps->lit_len;
	ps->lit = NULL;
	ps->lit_len = 0;
	ps->t = TOKEN_NA;
	ps->c = *ps->pos;

	TFW_DBG3("tfsm start, char: '%c', pos: %.20s\n", ps->c, ps->pos);

	FSM_JMP(TS_START_NEW_TOKEN);

	/* The next character is read at _TFSM_MOVE(), so we have a fresh
	 * character automatically whenever we enter a state. */

	FSM_STATE(TS_START_NEW_TOKEN) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* A backslash means that the next character definitely has
		 * no special meaning and thus starts a literal. */
		FSM_COND_JMP(ps->c == '\\', TS_LITERAL_FIRST_CHAR);

		/* Eat non-is_escaped spaces. */
		TFSM_COND_SKIP(isspace(ps->c));

		/* A character next to a double quote is the first character
		 * of a literal. The quote itself is not included to the
		 * literal's value. */
		TFSM_COND_MOVE(ps->c == '"', TS_QUOTED_LITERAL_FIRST_CHAR);

		/* A comment is starts with '#' (and ends with a like break) */
		TFSM_COND_MOVE(ps->c == '#', TS_COMMENT);

		/* Self-meaning single-character tokens. */
		TFSM_COND_MOVE_EXIT(ps->c == '{', TOKEN_LBRACE);
		TFSM_COND_MOVE_EXIT(ps->c == '}', TOKEN_RBRACE);
		TFSM_COND_MOVE_EXIT(ps->c == ';', TOKEN_SEMICOLON);

		/* Self-meaning double-character tokens. */
		TFSM_COND_MOVE(ps->c == '!' || ps->c == '-', TS_DCHAR);

		/* Special cases to determine double-character tokens during
		 * literals accumulating. */
		TFSM_COND_MOVE_EXIT(ps->c == '=' && ps->prev_c == '!',
				    TOKEN_NEQSIGN);
		TFSM_COND_MOVE_EXIT(ps->c == '>' && ps->prev_c == '-',
				    TOKEN_ARROW);

		/* Special case to differ single equal sign from double one. */
		TFSM_COND_MOVE(ps->c == '=', TS_EQSIGN);

		/* Everything else is not a special character and therefore
		 * it starts a literal. */
		FSM_JMP(TS_LITERAL_FIRST_CHAR);
	}

	FSM_STATE(TS_DCHAR) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* Jump to literals accumulating, if '!=' or '->' tokens are
		 * not matched. */
		TFSM_COND_MOVE_EXIT(ps->c == '=' && ps->prev_c == '!',
				    TOKEN_NEQSIGN);
		TFSM_COND_MOVE_EXIT(ps->c == '>' && ps->prev_c == '-',
				    TOKEN_ARROW);
		ps->lit = ps->pos - 1;
		++ps->lit_len;
		FSM_JMP(TS_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_EQSIGN) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* If this is double equal sign, eat second sign and exit. */
		TFSM_COND_MOVE_EXIT(ps->c == '=', TOKEN_DEQSIGN);
		TFSM_JMP_EXIT(TOKEN_EQSIGN);
	}

	FSM_STATE(TS_COMMENT) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* Eat everything until a new line is reached.
		 * The line break cannot be is_escaped within a comment. */
		TFSM_COND_SKIP(ps->c != '\n');
		TFSM_MOVE(TS_START_NEW_TOKEN);
	}

	FSM_STATE(TS_LITERAL_FIRST_CHAR) {
		ps->lit = ps->pos;
		FSM_JMP(TS_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_LITERAL_ACCUMULATE) {
		/* EOF terminates a literal if there is any chars saved. */
		TFSM_COND_JMP_EXIT(!ps->c && !ps->lit_len, TOKEN_NA);
		TFSM_COND_JMP_EXIT(!ps->c && ps->lit_len, TOKEN_LITERAL);

		/* Accumulate backslash together with any next character. */
		TFSM_COND_MOVE(ps->c == '\\', TS_LITERAL_ACC_ESCAPE);

		/* Non-escaped special characters terminate the literal. */
		TFSM_COND_JMP_EXIT(isspace(ps->c), TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '"', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '#', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '{', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '}', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == ';', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '=', TOKEN_LITERAL);

		/* Non-escaped first char of double-character special tokens. */
		TFSM_COND_MOVE(ps->c == '-' || ps->c == '!',
			       TS_DOUBLE_CHARACTER_FIRST_CHAR);

		/* Accumulate everything else. */
		++ps->lit_len;
		TFSM_SKIP();
	}

	FSM_STATE(TS_LITERAL_ACC_ESCAPE) {
		ps->lit_len += 2;
		TFSM_MOVE(TS_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_QUOTED_LITERAL_FIRST_CHAR) {
		ps->lit = ps->pos;
		FSM_JMP(TS_QUOTED_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_QUOTED_LITERAL_ACCUMULATE) {
		/* EOF means there is no matching double quote. */
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* A double quote terminates the literal,
		 * but it may be escaped with a backslash. */
		TFSM_COND_MOVE(ps->c == '\\', TS_QUOTED_LIT_ACC_ESCAPE);
		TFSM_COND_MOVE_EXIT(ps->c == '"', TOKEN_LITERAL);

		/* Everything else is accumulated (including line breaks). */
		++ps->lit_len;
		TFSM_SKIP();
	}

	FSM_STATE(TS_QUOTED_LIT_ACC_ESCAPE) {
		ps->lit_len += 2;
		TFSM_MOVE(TS_QUOTED_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_DOUBLE_CHARACTER_FIRST_CHAR) {
		/* Check double-character tokens and continue accumulate
		 * literal, if not matched. */
		TFSM_COND_JMP_EXIT(ps->c == '>' && ps->prev_c == '-',
				   TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '=' && ps->prev_c == '!',
				   TOKEN_LITERAL);
		++ps->lit_len;
		FSM_JMP(TS_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_EXIT) {
		TFW_DBG3("tfsm exit: t: %d, lit: %.*s\n",
			 ps->t, ps->lit_len, ps->lit);
	}
}

static int
entry_set_cond(TfwCfgEntry *e, token_t cond_type, const char *src, int len)
{
	const char *name = TFW_CFG_RULE_NAME;
	int name_len = sizeof(TFW_CFG_RULE_NAME) - 1;
	TfwCfgRule *rule = &e->rule;

	BUG_ON(!e->ftoken);
	BUG_ON(e->name);

	TFW_DBG3("set entry rule name '%.*s', 1st operand '%.*s', 2nd operand"
		 " '%.*s', and condition type '%d'\n", name_len, name,
		 (int)strlen(e->ftoken), e->ftoken, len, src, cond_type);

	if (!src || !len)
		return -EINVAL;

	rule->fst = e->ftoken;
	e->ftoken = NULL;

	if (!(rule->snd = alloc_and_copy_literal_bs(src, len)))
		return -ENOMEM;

	if (!(e->name = alloc_and_copy_literal(name, name_len)))
		return -ENOMEM;

	rule->inv = cond_type == TOKEN_DEQSIGN ? false : true;
	return 0;
}

/**
 * The PFSM (Parser Finite State Machine).
 *
 * Steps over a stream of tokens (produces by the TFSM), accumulates values
 * in TfwCfgEntry and returns it when the input entry is terminated with ';'.
 * Returns one entry at a time and shifts the input position accordingly.
 * Should be called in a loop until NULL is returned.
 *
 * Doesn't recurse into nested entries.
 * I.e. it doesn't fully parse this:
 *   entry1 {
 *       entry2;
 *   }
 * Instead, it stops at the '{' character and the higher-level code has to use
 * push-down automaton approach to parse the section between '{' and '}'.
 * That is done because we are not going to complicate things here by building
 * a large syntax tree and creating a DSL to query it.
 */
static void
parse_cfg_entry(TfwCfgParserState *ps)
{
	TFW_DBG3("pfsm: start\n");
	BUG_ON(ps->err);

	/* Start of the input? Read the first token and start a new entry. */
	if (ps->in == ps->pos) {
		read_next_token(ps);
		if (!ps->t)
			FSM_JMP(PS_EXIT);
	}

	/* Continue: start a new entry at the current position. */
	BUG_ON(!ps->t);
	FSM_JMP(PS_START_NEW_ENTRY);

	/* Every _PFSM_MOVE() invokes _read_next_token(), so when we enter
	 * any state, we get a new token automatically.
	 * Four different situations may occur here:
	 * 1. In case of plain directive parsing:
	 *    name key = value;
	 *    ^
	 * 2. In case of rule parsing:
	 *    key == (!=) value -> action [= val]
	 *    ^
	 * 3. In case of extended rule parsing:
	 *    key key_ext == (!=) value -> action [= val]
	 *    ^
	 * 4. In case of parsing of pure action rule:
	 *    -> action [= val]
	 *    ^
	 * current token is here; so at first we need to differentiate fourth
	 * situation, and in first three ones - save first token in special location
	 * to decide later whether use it as name for plain directive or as
	 * condition key for rule; in last three cases predefined rule name is used.
	 */
	FSM_STATE(PS_START_NEW_ENTRY) {
		entry_reset(&ps->e);
		ps->e.line_no = ps->line_no;
		ps->e.line = ps->line;

		PFSM_COND_MOVE(ps->t == TOKEN_ARROW, PS_RULE_PURE_ACTION);

		ps->err = entry_set_first_token(&ps->e, ps->lit, ps->lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);

		PFSM_MOVE(PS_PLAIN_OR_RULE);
	}

	FSM_STATE(PS_PLAIN_OR_RULE) {
		PFSM_COND_MOVE(ps->t == TOKEN_DEQSIGN ||
			       ps->t == TOKEN_NEQSIGN,
			       PS_RULE_COND);
		PFSM_COND_MOVE(ps->t == TOKEN_LITERAL, PS_PLAIN_OR_LONG_RULE);

		/* Jump to plain val/attr scheme to make remained checks
		 * for left brace and semicolon. */
		ps->err = entry_set_name(&ps->e);
		FSM_COND_JMP(ps->err, PS_EXIT);
		FSM_JMP(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_PLAIN_OR_LONG_RULE) {
		FSM_COND_JMP(ps->t == TOKEN_DEQSIGN ||
			     ps->t == TOKEN_NEQSIGN,
			     PS_LONG_RULE_COND);

		/* This is not rule (simple or extended), so jump to
		 * plain val/attr scheme. */
		ps->err = entry_set_name(&ps->e);
		FSM_COND_JMP(ps->err, PS_EXIT);
		FSM_COND_JMP(ps->t == TOKEN_EQSIGN, PS_STORE_ATTR_PREV);
		FSM_COND_JMP(ps->t == TOKEN_LITERAL ||
			     ps->t == TOKEN_SEMICOLON ||
			     ps->t == TOKEN_LBRACE,
			     PS_STORE_VAL_PREV);

		ps->err = -EINVAL;
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_LONG_RULE_COND) {
		ps->err = entry_add_rule_param(&ps->e.rule.fst_ext,
					       ps->prev_lit,
					       ps->prev_lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);
		PFSM_MOVE(PS_RULE_COND);
	}

	FSM_STATE(PS_RULE_COND) {
		PFSM_COND_JMP_EXIT_ERROR(ps->t != TOKEN_LITERAL);
		ps->err = entry_set_cond(&ps->e, ps->prev_t, ps->lit,
					 ps->lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);
		PFSM_MOVE(PS_RULE_COND_END);
	}

	FSM_STATE(PS_RULE_COND_END) {
		PFSM_COND_JMP_EXIT_ERROR(ps->t != TOKEN_ARROW);
		PFSM_MOVE(PS_RULE_ACTION);
	}

	FSM_STATE(PS_RULE_PURE_ACTION) {
		ps->err = entry_set_name(&ps->e);
		FSM_COND_JMP(ps->err, PS_EXIT);
		FSM_JMP(PS_RULE_ACTION);
	}

	FSM_STATE(PS_RULE_ACTION) {
		PFSM_COND_JMP_EXIT_ERROR(ps->t != TOKEN_LITERAL);
		ps->err = entry_add_rule_param(&ps->e.rule.act, ps->lit,
					       ps->lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);
		PFSM_MOVE(PS_RULE_ACTION_VAL);
	}

	FSM_STATE(PS_RULE_ACTION_VAL) {
		FSM_COND_JMP(ps->t == TOKEN_SEMICOLON, PS_SEMICOLON);
		PFSM_COND_JMP_EXIT_ERROR(ps->t != TOKEN_EQSIGN);
		read_next_token(ps);
		PFSM_COND_JMP_EXIT_ERROR(ps->t != TOKEN_LITERAL);

		ps->err = entry_add_rule_param(&ps->e.rule.val, ps->lit,
					       ps->lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);

		read_next_token(ps);
		PFSM_COND_JMP_EXIT_ERROR(ps->t != TOKEN_SEMICOLON);
		FSM_JMP(PS_SEMICOLON);
	}

	/*
	 * Now we have a situation where at current position we don't know
	 * whether we have a value or an attribute:
	 *     name key = value;
	 *          ^
	 *          current position here
	 *
	 * An implementation of peek_token() would be tricky here because the
	 * TFSM is not pure (it alters the current state). So instead of looking
	 * forward, we move to the next position and look to the '=' sign:
	 * if it is there - then we treat previous value as an attribute name,
	 * otherwise we save it as a value of the current node.
	 */

	FSM_STATE(PS_VAL_OR_ATTR) {
		PFSM_COND_MOVE(ps->t == TOKEN_LITERAL, PS_MAYBE_EQSIGN);
		FSM_COND_JMP(ps->t == TOKEN_SEMICOLON, PS_SEMICOLON);
		FSM_COND_JMP(ps->t == TOKEN_LBRACE, PS_LBRACE);

		ps->err = -EINVAL;
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_MAYBE_EQSIGN) {
		FSM_COND_JMP(ps->t == TOKEN_EQSIGN, PS_STORE_ATTR_PREV);
		FSM_JMP(PS_STORE_VAL_PREV);
	}

	FSM_STATE(PS_STORE_VAL_PREV) {
		/* name val1 val2;
		 *           ^
		 *           We are here (but still need to store val1). */
		TFW_DBG3("add value: %.*s\n", ps->prev_lit_len, ps->prev_lit);

		ps->err = entry_add_val(&ps->e, ps->prev_lit, ps->prev_lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);

		FSM_JMP(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_STORE_ATTR_PREV) {
		/* name key = val;
		 *          ^
		 *          We are here. */
		const char *key, *val;
		int key_len, val_len;

		key = ps->prev_lit;
		key_len = ps->prev_lit_len;
		read_next_token(ps);  /* eat '=' */
		val = ps->lit;
		val_len = ps->lit_len;

		TFW_DBG3("add attr: %.*s = %.*s\n", key_len, key, val_len, val);

		ps->err = entry_add_attr(&ps->e, key, key_len, val, val_len);
		FSM_COND_JMP(ps->err, PS_EXIT);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_LBRACE) {
		/* Simply exit on '{' leaving nested nodes untouched and
		 * surrounded with braces. The caller should detect it and parse
		 * them in a loop. */
		ps->e.have_children = true;
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_SEMICOLON) {
		/* Simply eat ';'. Don't MOVE because the next character may be
		 * '\0' and that triggers an error (because we expect more input
		 * tokens when we do _PFSM_MOVE()). */
		read_next_token(ps);
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_EXIT) {
		/* Cleanup of entry is done in tfw_cfg_parse_mods() */
		TFW_DBG3("pfsm: exit\n");
	}
}

/*
 * ------------------------------------------------------------------------
 *	Configuration Parser - TfwCfgSpec helpers.
 * ------------------------------------------------------------------------
 *
 * The configuration parsing is done slightly differently depending on the
 * context (top-level vs recursing into children entries), but the TfwCfgSpec
 * is handled in the same way in both cases. So the code below is the shared
 * logic between these two cases.
 */

static TfwCfgSpec *
spec_find(TfwCfgSpec specs[], const char *name)
{
	TfwCfgSpec *spec;

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (!strcmp(spec->name, name))
			return spec;
	}

	return NULL;
}

static int
__spec_start_handling(TfwCfgSpec *parent, TfwCfgSpec specs[])
{
	TfwCfgSpec *spec;

	BUG_ON(!specs);

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		BUG_ON(!spec->name);
		BUG_ON(!*spec->name);
		BUG_ON(!check_identifier(spec->name, strlen(spec->name)));
		BUG_ON(!spec->handler);
		if (spec->handler == &tfw_cfg_handle_children)
			BUG_ON(!spec->cleanup);
		if (parent && !parent->allow_reconfig && spec->allow_reconfig) {
			TFW_WARN_NL("Directive '%s' doesn't allow "
				    "reconfiguration required for directive '%s'"
				    "\n",
				    parent->name, spec->name);
			return -EINVAL;
		}
		spec->__called_now = false;
	}

	return 0;
}

static void
spec_start_handling(TfwCfgSpec specs[])
{
	__spec_start_handling(NULL, specs);
}

static int
spec_handle_entry(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry)
{
	int r;
	bool dont_reconfig = tfw_runstate_is_reconfig() && !spec->allow_reconfig;

	if (!spec->allow_repeat && spec->__called_now) {
		TFW_ERR_NL("duplicate entry: '%s', only one such entry is"
			   " allowed.\n", parsed_entry->name);
		return -EINVAL;
	}
	spec->__called_now = true;

	/*
	 * Continue parsing configuration section, if the whole section is
	 * not allowed to be applied in reconfig, tfw_cfg_handle_children()
	 * will handle it.
	 */
	if (dont_reconfig && (spec->handler != &tfw_cfg_handle_children)) {
		TFW_DBG2("skip spec '%s': reconfig not allowed\n", spec->name);
		return 0;
	}
	TFW_DBG2("spec handle: '%s'\n", spec->name);
	r = spec->handler(spec, parsed_entry);
	if (dont_reconfig) {
		TFW_DBG2("spec '%s' skipped: reconfig not allowed\n", spec->name);
		return r;
	}

	spec->__called_cfg = true;
	if (r)
		TFW_DBG("configuration handler returned error: %d\n", r);

	return r;
}

/**
 * Handle TfwCfgSpec->deflt . That is done by constructing a buffer containing
 * fake configuration text and parsing it as if it was a real configuration.
 * The parsed TfwCfgEntry then is passed to the TfwCfgSpec->handler as usual.
 *
 * TODO: refactoring. The code is not elegant.
 */
static int
spec_handle_default(TfwCfgSpec *spec)
{
	int len, r;
	static char fake_entry_buf[PAGE_SIZE];
	static TfwCfgParserState ps;

	len = snprintf(fake_entry_buf, sizeof(fake_entry_buf), "%s %s;",
		 spec->name, spec->deflt);
	BUG_ON(len >= sizeof(fake_entry_buf));

	TFW_DBG2("use default entry: '%s'\n", fake_entry_buf);

	memset(&ps, 0, sizeof(ps));
	ps.line = ps.in = ps.pos = fake_entry_buf;
	parse_cfg_entry(&ps);
	BUG_ON(!ps.e.name);
	BUG_ON(ps.err);
	BUG_ON(ps.t != TOKEN_NA);

	ps.e.dflt_value = true;
	r = spec_handle_entry(spec, &ps.e);
	entry_reset(&ps.e);
	return r;
}

static int spec_finish_handling(TfwCfgSpec specs[]);

static int
spec_handle_default_section(TfwCfgSpec *spec)
{
	if (spec->handler != tfw_cfg_handle_children)
		return 0;
	TFW_DBG2("use default values for section '%s'\n", spec->name);
	if (spec->dest == NULL)
		return 0;
	return spec_finish_handling(spec->dest);
}

static int
spec_finish_handling(TfwCfgSpec specs[])
{
	int r;
	TfwCfgSpec *spec;

	/* Here we are interested in specs that were not triggered during
	 * the configuration parsing. There are three cases here:
	 *  1. deflt != NULL
	 *     Ok: just use the default value instead of real configuration.
	 *  2. deflt == NULL && allow_none == true
	 *     Ok: no such entry parsed at all (including the default),
	 *     but this is allowed, so do nothing.
	 *  3. deflt == NULL && allow_none == false
	 *     Error: the field is not optional, no such entry parsed and no
	 *     default value is provided, so issue an error.
	 */
	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (spec->__called_now)
			continue;
		if (spec->handler == tfw_cfg_handle_children) {
			if (!spec->allow_none)
				/* Whole section absent */
				if ((r = spec_handle_default_section(spec)))
					goto err_dflt_val;
		} else if (spec->deflt) {
			if ((r = spec_handle_default(spec)))
				goto err_dflt_val;
		} else if (!spec->allow_none) {
			/* Jump just because TFW_ERR() is ugly here. */
			goto err_no_entry;
		}
	}

	return 0;

err_no_entry:
	TFW_ERR_NL("the required entry is not found: '%s'\n", spec->name);
	return -EINVAL;

err_dflt_val:
	TFW_ERR_NL("Error handling default value for: '%s'\n", spec->name);
	return r;
}

static void
spec_cleanup(TfwCfgSpec specs[])
{
	TfwCfgSpec *spec;
	bool called, reconfig = tfw_runstate_is_reconfig();

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		called = spec->__called_cfg;
		spec->__called_cfg = false;
		if (!reconfig) {
			called |= spec->__called_ever;
			spec->__called_ever = false;
		}
		if (called && spec->cleanup) {
			TFW_DBG2("%s: '%s'\n", __func__, spec->name);
			spec->cleanup(spec);
		}
	}
}

/*
 * ------------------------------------------------------------------------
 *	Configuration parser - generic TfwCfgSpec->handlers functions
 *	and other helpers for writing custom handlers.
 * ------------------------------------------------------------------------
 */

int
tfw_cfg_map_enum(const TfwCfgEnum mappings[],
		 const char *in_name, void *out_int)
{
	int *out;
	const TfwCfgEnum *pos;

	/* The function writes an int, but usually you want to pass an enum
	 * as the @out_int, so ensure check that their sizes are equal.
	 * Beware: that doesn't protect from packed enums. You may get a memory
	 * corruption if you pass an enum __attribute__((packed)) as @out_int.
	 */
	typedef enum { _DUMMY } _dummy;
	BUILD_BUG_ON(sizeof(_dummy) != sizeof(int));

	BUG_ON(!mappings);
	BUG_ON(!in_name);
	BUG_ON(!out_int);

	for (pos = mappings; pos->name; ++pos) {
		BUG_ON(!check_identifier(pos->name, strlen(pos->name)));
		if (!strcasecmp(in_name, pos->name)) {
			out = out_int;
			*out = pos->value;
			return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(tfw_cfg_map_enum);

/**
 * Get value of attribute with name @attr_key.
 * Return @default_val if the attribute is not found in the entry @e.
 */
const char *
tfw_cfg_get_attr(const TfwCfgEntry *e, const char *attr_key,
		 const char *default_val)
{
	size_t i;
	const char *key, *val;

	TFW_CFG_ENTRY_FOR_EACH_ATTR(e, i, key, val) {
		if (!strcasecmp(key, attr_key))
			return val;
	}

	return default_val;
}
EXPORT_SYMBOL(tfw_cfg_get_attr);

/**
 * Check that integer is in specified range.
 * Print an error and return non-zero if it is out of range.
 */
int
tfw_cfg_check_range(long value, long min, long max)
{
	if (min != max && (value < min || value > max)) {
		TFW_ERR_NL("the value %ld is out of range: [%ld, %ld]\n",
			   value, min, max);
		return -ERANGE;
	}
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_check_range);

/**
 * Check that integer @value is a multiple of @divisor (print an error
 * otherwise);
 */
int
tfw_cfg_check_multiple_of(long value, int divisor)
{
	if (divisor && (value % divisor)) {
		TFW_ERR_NL("the value of %ld is not a multiple of %d\n",
			   value, divisor);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_check_multiple_of);

/**
 * Check that the entry @e has exactly @val_n values.
 */
int
tfw_cfg_check_val_n(const TfwCfgEntry *e, int val_n)
{
	if (e->val_n != val_n) {
		TFW_ERR_NL("invalid number of values; expected: %d, got: %zu\n",
			   val_n, e->val_n);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_check_val_n);

/**
 * Most of the handlers below work with single-value entries like this:
 *   option1 42;
 *   option2 true;
 *   option3 192.168.1.1;
 *
 * This function helps those handlers to check that the input entry matches
 * to the expected pattern: single value, no attributes, no children entries.
 */
int
tfw_cfg_check_single_val(const TfwCfgEntry *e)
{
	int r = -EINVAL;

	if (e->val_n == 0)
		TFW_ERR_NL("no value specified\n");
	else if (e->val_n > 1)
		TFW_ERR_NL("more than one value specified\n");
	else if (e->attr_n)
		TFW_ERR_NL("unexpected attributes\n");
	else if (e->have_children)
		TFW_ERR_NL("unexpected children entries\n");
	else
		r = 0;

	return r;
}
EXPORT_SYMBOL(tfw_cfg_check_single_val);

/**
 * Detect integer base and strip 0x and 0b prefixes from the string.
 *
 * The custom function is written because the kstrtox() treats leading zeros as
 * the octal base. That may cause an unexpected effect when you specify "010" in
 * the configuration and get 8 instead of 10. We want to avoid that.
 *
 * As a bonus, we have the "0b" support here. This may be handy for specifying
 * some masks and bit strings in the configuration.
 */
static int
detect_base(const char **pos)
{
	const char *str = *pos;
	size_t len = strlen(str);

	if (!len)
		return 0;

	if (len > 2 && str[0] == '0' && isalpha(str[1])) {
		char c = tolower(str[1]);

		(*pos) += 2;

		if (c == 'x')
			return 16;
		else if (c == 'b')
			return 2;
		else
			return 0;
	}

	return 10;
}

int
__tfw_cfg_parse_int(const char *s, int *out_int)
{
	int base = detect_base(&s);
	if (!base)
		return -EINVAL;
	return kstrtoint(s, base, out_int);
}

int
tfw_cfg_parse_int(const char *s, int *out_int)
{
	int r = __tfw_cfg_parse_int(s, out_int);
	if (r)
		TFW_ERR_NL("Can't parse '%s' as 'int'\n", s);
	return r;
}
EXPORT_SYMBOL(tfw_cfg_parse_int);

int
tfw_cfg_parse_uint(const char *s, unsigned int *out_uint)
{
	int r = -EINVAL, base;

	if (!(base = detect_base(&s)))
		goto err;
	if ((r = kstrtouint(s, base, out_uint)))
		goto err;

	return 0;
err:
	TFW_ERR_NL("Can't parse '%s' as 'unsigned int'\n", s);
	return r;
}
EXPORT_SYMBOL(tfw_cfg_parse_uint);

int
tfw_cfg_parse_long(const char *s, long *out_long)
{
	int r = -EINVAL, base;

	if (!(base = detect_base(&s)))
		goto err;
	if ((r = kstrtol(s, base, out_long)))
		goto err;

	return 0;
err:
	TFW_ERR_NL("Can't parse '%s' as 'long'\n", s);
	return r;
}
EXPORT_SYMBOL(tfw_cfg_parse_long);

/**
 * Borrowed from linux/lib/kstrtox.c because the function isn't exported by
 * the kernel.
 */
#define KSTRTOX_OVERFLOW	(1U << 31)

static unsigned int
_parse_integer(const char *s, unsigned int base, unsigned long *p)
{
	unsigned long res;
	unsigned int rv;

	res = 0;
	rv = 0;
	while (1) {
		unsigned int c = *s;
		unsigned int lc = c | 0x20; /* don't tolower() this line */
		unsigned int val;

		if ('0' <= c && c <= '9')
			val = c - '0';
		else if ('a' <= lc && lc <= 'f')
			val = lc - 'a' + 10;
		else
			break;

		if (val >= base)
			break;
		/*
		 * Check for overflow only if we are within range of
		 * it in the max base we support (16)
		 */
		if (unlikely(res & (~0ull << 60))) {
			if (res > div_u64(ULLONG_MAX - val, base))
				rv |= KSTRTOX_OVERFLOW;
		}
		res = res * base + val;
		rv++;
		s++;
	}
	*p = res;

	return rv;
}

int
tfw_cfg_parse_intvl(const char *str, unsigned long *i0, unsigned long *i1)
{
	const char *s = str;
	unsigned long *v = i0;
	unsigned int r;
	int base;

	while (*s) {
		if (*s == '-') {
			if (v == i1) {
				TFW_ERR_NL("Bad interval delimiter\n");
				return -EINVAL;
			}
			v = i1;
			++s;
			continue;
		}

		base = detect_base(&s);
		if (!base)
			return -EINVAL;
		r = _parse_integer(s, base, v);
		if (!r || r & KSTRTOX_OVERFLOW) {
			TFW_ERR_NL("Bad integer\n");
			return -EINVAL;
		}
		if (v == i1 && *i0 >= *i1) {
			TFW_ERR("Interval bound crossing\n");
			return -EINVAL;
		}

		s += r;
	}
	if (v == i1 && !*v) {
		TFW_ERR_NL("Zero interval left bound in '%s'\n", str);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_parse_intvl);

void
tfw_cfg_cleanup_children(TfwCfgSpec *cs)
{
	TfwCfgSpec *nested_specs = cs->dest;
	spec_cleanup(nested_specs);
}
EXPORT_SYMBOL(tfw_cfg_cleanup_children);

/**
 * This handler allows to parse nested entries recursively.
 *
 * @arg must be an array of TfwCfgSpec structures which is applied to nested
 * entries.
 *
 * When there are nested entries, the parse_and_handle_cfg_entry()
 * stops at this position:
 *         v
 * section {
 *     option1;
 *     option2;
 *     option3;
 *     ...
 * }
 * ...and invokes the TfwCfgSpec->handler which turns out to be this function.
 * Here we simply continue parsing by recursing to parse_and_handle_cfg_entry().
 *
 * Also, we cheat here: we don't create a new TfwCfgParserState, but rather
 * continue using the parent state. We know that the TfwCfgEntry is the part
 * of the parent state, so we simply restore it with container_of().
 */
int
tfw_cfg_handle_children(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	TfwCfgParserState *ps = container_of(e, TfwCfgParserState, e);
	TfwCfgSpecChild *cse = cs->spec_ext;
	TfwCfgSpec *nested_specs = cs->dest;
	TfwCfgSpec *matching_spec;
	int ret;
	bool run_hooks = !tfw_runstate_is_reconfig() || cs->allow_reconfig;

	BUG_ON(!nested_specs);
	BUG_ON(!cs->cleanup);

	if (!e->have_children) {
		TFW_ERR_NL("the entry has no nested children entries\n");
		return -EINVAL;
	}

	/* Call TfwCfgSpecChild->begin_hook before parsing anything. */
	ret = (run_hooks && cse && cse->begin_hook) ? cse->begin_hook(cs, e) : 0;
	if (ret)
		return ret;

	/* Prepare child TfwCfgSpec for parsing. */
	if ((ret = __spec_start_handling(cs, nested_specs)))
		return ret;

	/*
	 * We get to this function when the caller finds
	 * an opening brace. Confirm we have a '{' here.
	 */
	BUG_ON(ps->t != TOKEN_LBRACE);

	read_next_token(ps);
	if (ps->err)
		return ps->err;

	/* Walk over children entries. */
	while (ps->t && (ps->t != TOKEN_RBRACE)) {
		parse_cfg_entry(ps);
		if (ps->err) {
			TFW_ERR_NL("parser error\n");
			return ps->err;
		}

		matching_spec = spec_find(nested_specs, ps->e.name);
		if (!matching_spec) {
			TFW_ERR_NL("don't know how to handle: %s\n", ps->e.name);
			return -EINVAL;
		}

		ret = spec_handle_entry(matching_spec, &ps->e);
		if (ret)
			return ret;
		entry_reset(&ps->e);
	}

	/*
	 * Normally, we get out of the loop when a closing brace
	 * is found. Otherwise, there's an error in configuration.
	 * Check that we have a '}' here.
	 */
	if (ps->t != TOKEN_RBRACE) {
		TFW_ERR_NL("%s: Missing closing brace.\n", cs->name);
		return -EINVAL;
	}

	read_next_token(ps);
	if (ps->err)
		return ps->err;
	ret = spec_finish_handling(nested_specs);
	if (ret)
		return ret;

	/* Children entries are parsed, call TfwCfgSpecChild->finish_hook. */
	ret = (run_hooks && cse && cse->finish_hook) ? cse->finish_hook(cs) : 0;
	return ret;
}
EXPORT_SYMBOL(tfw_cfg_handle_children);

int
tfw_cfg_set_bool(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	bool is_true, is_false;
	bool *dest_bool = cs->dest;
	const char *in_str = e->vals[0];

	BUG_ON(!dest_bool);

	/* Handle simple flag without a value.
	 * Usually it looks like this:
	 *   backend 127.0.0.1:8001 {
	 *      health_check;
	 *      ...;
	 *   }
	 */
	if (!e->val_n && !e->attr_n && !e->have_children) {
		*dest_bool = true;
		return 0;
	}

	/* Handle explicit (single) value, for example:
	 *   feature on;
	 *   feature off;
	 */
	if (tfw_cfg_check_single_val(e))
		return -EINVAL;

	is_true =  !strcasecmp(in_str, "1")
	        || !strcasecmp(in_str, "y")
	        || !strcasecmp(in_str, "on")
	        || !strcasecmp(in_str, "yes")
	        || !strcasecmp(in_str, "true")
	        || !strcasecmp(in_str, "enable");

	is_false =  !strcasecmp(in_str, "0")
	         || !strcasecmp(in_str, "n")
	         || !strcasecmp(in_str, "off")
	         || !strcasecmp(in_str, "no")
	         || !strcasecmp(in_str, "false")
	         || !strcasecmp(in_str, "disable");

	BUG_ON(is_true && is_false);
	if (!is_true && !is_false) {
		TFW_ERR_NL("invalid boolean value: '%s'\n", in_str);
		return -EINVAL;
	}

	*dest_bool = is_true;
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_set_bool);

static int
__tfw_cfg_set_int(TfwCfgSpec *cs, TfwCfgEntry *e, bool is_long)
{
	int r;
	int int_val = 0;
	long val;
	const char *in_str;
	TfwCfgSpecInt *cse = cs->spec_ext;

	BUG_ON(!cs->dest);

	if ((r = tfw_cfg_check_single_val(e)))
		return -EINVAL;
	in_str = e->vals[0];

	/* First, try to substitute an enum keyword with an integer value. */
	if (cse && cse->enums
	    && !tfw_cfg_map_enum(cse->enums, in_str, &int_val))
	{
		val = int_val;
		goto val_is_parsed;
	}

	if (is_long) {
		r = tfw_cfg_parse_long(in_str, &val);
	}
	else {
		r = tfw_cfg_parse_int(in_str, &int_val);
		val = int_val;
	}
	if (r)
		return r;

val_is_parsed:
	/* Check value restrictions if we have any in the spec extension. */
	if (cse) {
		r  = tfw_cfg_check_multiple_of(val, cse->multiple_of);
		r |= tfw_cfg_check_range(val, cse->range.min, cse->range.max);
		if (r)
			return r;
	}

	if (is_long)
		*(long *)cs->dest = val;
	else
		*(int *)cs->dest = val;

	return 0;
}

int
tfw_cfg_set_int(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	return __tfw_cfg_set_int(cs, e, false);
}
EXPORT_SYMBOL(tfw_cfg_set_int);

int
tfw_cfg_set_long(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	return __tfw_cfg_set_int(cs, e, true);
}
EXPORT_SYMBOL(tfw_cfg_set_long);

static void
tfw_cfg_cleanup_str(TfwCfgSpec *cs)
{
	char **strp = cs->dest;
	char *str = *strp;

	/* The function may only be called when memory was allocated. */
	BUG_ON(!str);
	kfree(str);
	*strp = NULL;
	cs->cleanup = NULL;
}

static bool
is_matching_to_cset(const char *p, const char *cset)
{
	while (*p) {
		if (!strchr(cset, *p))
			return false;
		++p;
	}
	return true;
}

int
tfw_cfg_set_str(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	const char **dest_strp;
	int r;

	BUG_ON(!cs);
	BUG_ON(!cs->dest);
	BUG_ON(cs->cleanup);

	r = tfw_cfg_check_single_val(e);
	if (r)
		return r;

	if (cs->spec_ext) {
		TfwCfgSpecStr *cse = cs->spec_ext;
		const char *str, *cset;
		int min, max, len;

		str = e->vals[0];
		len = strlen(str);

		min = cse->len_range.min;
		max = cse->len_range.max;
		if (min != max && (len < min || len > max)) {
			TFW_ERR_NL("the string length (%d) is out of valid "
				   "range (%d, %d): '%s'\n", len, min, max,
				   str);
			return -EINVAL;
		}

		cset = cse->cset;
		if (cset && !is_matching_to_cset(str, cset)) {
			TFW_ERR_NL("invalid characters found: '%s'\n", str);
			return -EINVAL;
		}
	}

	/* Simply steal the dynamically allocated value from the TfwCfgEntry
	 * and set a callback to free it properly. */
	dest_strp = cs->dest;
	*dest_strp = e->vals[0];
	e->vals[0] = NULL;
	cs->cleanup = tfw_cfg_cleanup_str;

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_set_str);

/*
 * ------------------------------------------------------------------------
 *	Handling list of modules, the top-level parsing routines.
 * ------------------------------------------------------------------------
 */
/*
 * The file path is passed via the kernel module parameter.
 * Usually you would not like to change it on a running system.
 */
static char *tfw_cfg_path = TFW_CFG_PATH;
module_param(tfw_cfg_path, charp, 0444);
MODULE_PARM_DESC(tfw_cfg_path, "Path to Tempesta FW configuration file."
			       " Must be absolute.");

static void
print_parse_error(const TfwCfgParserState *ps)
{
	int len = 0;
	const char *ticks = "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
			    "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
	const char* eos = NULL;

	/*
	 * Line is not known: mandatory option is not present, error is raised
	 * by @spec_finish_handling() function.
	 */
	if (!ps->e.line) {
		TFW_ERR_NL("configuration parsing error\n");
		return;
	}

	eos = strchrnul(ps->e.line, '\n');
	len = min(80, (int)(eos - ps->e.line));
	TFW_ERR_NL("configuration parsing error:\n"
		   "%4zu: %.*s\n"
		   "      %.*s\n",
		   ps->e.line_no + 1, len, ps->e.line, len, ticks);
}

/*
 * Find configuration option specs by option name.
 * This is a helper function for outside use.
 * It is used in making dynamic additions to configuration.
 */
TfwCfgSpec *
tfw_cfg_spec_find(TfwCfgSpec specs[], const char *name)
{
	return spec_find(specs, name);
}
EXPORT_SYMBOL(tfw_cfg_spec_find);

/**
 * The top-level parsing routine.
 *
 * Parses @cfg_text and pushes the parsed data to all modules in the @mod_list.
 * For each parsed entry searches for a matching TfwCfgSpec across all specs
 * of all modules in the @mod_list.
 */
int
tfw_cfg_parse_mods(const char *cfg_text, struct list_head *mod_list)
{
	TfwCfgParserState ps = {
		.in = cfg_text,
		.pos = cfg_text,
		.line = cfg_text
	};
	TfwMod *mod;
	TfwCfgSpec *matching_spec = NULL;
	int r = -EINVAL;

	MOD_FOR_EACH(mod, mod_list) {
		spec_start_handling(mod->specs);
	}

	do {
		parse_cfg_entry(&ps);
		if (ps.err) {
			TFW_ERR_NL("syntax error\n");
			goto err;
		}
		if (!ps.e.name)
			break; /* EOF - nothing is parsed and no error. */

		MOD_FOR_EACH(mod, mod_list) {
			matching_spec = spec_find(mod->specs, ps.e.name);
			if (matching_spec)
				break;
		}
		if (!matching_spec) {
			TFW_ERR_NL("don't know how to handle: '%s'\n", ps.e.name);
			goto err;
		}

		r = spec_handle_entry(matching_spec, &ps.e);
		if (r)
			goto err;
		entry_reset(&ps.e);

		tfw_srv_loop_sched_rcu();
	} while (ps.t);

	MOD_FOR_EACH(mod, mod_list) {
		r = spec_finish_handling(mod->specs);
		if (r)
			goto err;
	}

	return 0;
err:
	print_parse_error(&ps);
	entry_reset(&ps.e);
	return -EINVAL;
}
EXPORT_SYMBOL(tfw_cfg_parse_mods);

/**
 * Clean up parsed configuration data in modules.
 */
void
tfw_cfg_cleanup(struct list_head *mod_list)
{
	TfwMod *mod;

	TFW_DBG3("Configuration cleanup...\n");
	MOD_FOR_EACH_REVERSE(mod, mod_list) {
		spec_cleanup(mod->specs);
		if (mod->cfgclean)
			mod->cfgclean();
		tfw_srv_loop_sched_rcu();
	}
}

int
tfw_cfg_parse(struct list_head *mod_list)
{
	int ret;
	size_t file_size = 0;
	char *cfg_text_buf;

	TFW_DBG3("reading configuration file...\n");
	if (!(cfg_text_buf = tfw_cfg_read_file(tfw_cfg_path, &file_size)))
		return -ENOENT;

	TFW_DBG2("parsing configuration and pushing it to modules...\n");
	if ((ret = tfw_cfg_parse_mods(cfg_text_buf, mod_list)))
		TFW_DBG("Error parsing configuration data\n");

	free_pages((unsigned long)cfg_text_buf, get_order(file_size));

	return ret;
}

static void
tfw_cfg_migrate_state(TfwCfgSpec *cs)
{
	TfwCfgSpec *spec;

	TFW_CFG_FOR_EACH_SPEC(spec, cs) {
		if (spec->__called_cfg)
			spec->__called_ever = true;
		if (spec->handler == &tfw_cfg_handle_children)
			tfw_cfg_migrate_state(spec->dest);
		spec->__called_cfg = false;
	}
}

void
tfw_cfg_conclude(struct list_head *mod_list)
{
	TfwMod *mod;

	MOD_FOR_EACH(mod, mod_list)
		tfw_cfg_migrate_state(mod->specs);
}

/*
 * ------------------------------------------------------------------------
 *	VFS helpers.
 * ------------------------------------------------------------------------
 */
/**
 * The functions returns a buffer containing the whole file.
 * The buffer must be freed with free_pages().
 */
void *
tfw_cfg_read_file(const char *path, size_t *file_size)
{
	char *out_buf;
	struct file *fp;
	ssize_t bytes_read;
	size_t read_size, buf_size;
	loff_t off = 0;
	mm_segment_t oldfs;

	if (!path || !*path) {
		TFW_ERR_NL("can't open file with empty name\n");
		return NULL;
	}

	TFW_DBG2("reading file: %s\n", path);

	oldfs = get_fs();
	set_fs(get_ds());

	fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR_OR_NULL(fp)) {
		TFW_ERR_NL("can't open file: %s (err: %ld)\n",
			   path, PTR_ERR(fp));
		goto err_open;
	}

	buf_size = fp->f_inode->i_size;
	TFW_DBG2("file size: %zu bytes\n", buf_size);
	buf_size += 1; /* for '\0' */
	*file_size = buf_size;

	out_buf = (char *)__get_free_pages(GFP_KERNEL, get_order(buf_size));
	if (!out_buf) {
		TFW_ERR_NL("can't allocate memory\n");
		goto err_alloc;
	}

	do {
		TFW_DBG3("read by offset: %d\n", (int)off);
		read_size = min((size_t)(buf_size - off), PAGE_SIZE);
		bytes_read = kernel_read(fp, out_buf + off, read_size, &off);
		if (bytes_read < 0) {
			TFW_ERR_NL("can't read file: %s (err: %zu)\n", path,
				bytes_read);
			goto err_read;
		}
	} while (bytes_read);

	/* Exactly one byte (reserved for '\0') should remain. */
	if (buf_size - off - 1) {
		TFW_ERR_NL("file size changed during the read: '%s'\n,", path);
		goto err_read;
	}

	filp_close(fp, NULL);

	out_buf[off] = '\0';
	set_fs(oldfs);
	return out_buf;

err_read:
	free_pages((unsigned long)out_buf, get_order(buf_size));
err_alloc:
	filp_close(fp, NULL);
err_open:
	set_fs(oldfs);
	return NULL;
}

int
tfw_cfg_init(void)
{
	return 0;
}

/**
 * The global shutdown routine: stop and un-register all modules,
 * and then un-register the sysctl interface.
 */
void
tfw_cfg_exit(void)
{
}
