/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "tempesta_fw.h"
#include "http.h"
#include "http_match.h"
#include "http_msg.h"
#include "vhost.h"
#include "str.h"
#include "http_limits.h"

/**
 * Control object for holding full set of virtual hosts specific for current
 * configuration/reconfiguration stage.
 *
 * @head	- List of configured virtual hosts.
 * @vhost_dflt	- Default virtual host with global policies (always present in
 *		  current configuration).
 * @expl_dflt	- Flag to indicate explicit configuration of default
 *		  virtual host.
 */
typedef struct {
	struct list_head head;
	TfwVhost	*vhost_dflt;
	bool		expl_dflt;
} TfwVhostList;

/* Mappings for match operators. */
static const TfwCfgEnum tfw_match_enum[] = {
	{ "*",		TFW_HTTP_MATCH_O_WILDCARD },
	{ "eq",		TFW_HTTP_MATCH_O_EQ },
	{ "prefix",	TFW_HTTP_MATCH_O_PREFIX },
	{ "suffix",	TFW_HTTP_MATCH_O_SUFFIX },
	{ 0 }
};

/* Mappings for HTTP request methods. */
static const TfwCfgEnum tfw_method_enum[] = {
	{ "*",		UINT_MAX },
	{ "COPY",	1 << TFW_HTTP_METH_COPY },
	{ "DELETE",	1 << TFW_HTTP_METH_DELETE },
	{ "GET",	1 << TFW_HTTP_METH_GET },
	{ "HEAD",	1 << TFW_HTTP_METH_HEAD },
	{ "LOCK",	1 << TFW_HTTP_METH_LOCK },
	{ "MKCOL",	1 << TFW_HTTP_METH_MKCOL },
	{ "MOVE",	1 << TFW_HTTP_METH_MOVE },
	{ "OPTIONS",	1 << TFW_HTTP_METH_OPTIONS },
	{ "PATCH",	1 << TFW_HTTP_METH_PATCH },
	{ "POST",	1 << TFW_HTTP_METH_POST },
	{ "PROPFIND",	1 << TFW_HTTP_METH_PROPFIND },
	{ "PROPPATCH",	1 << TFW_HTTP_METH_PROPPATCH },
	{ "PUT",	1 << TFW_HTTP_METH_PUT },
	{ "TRACE",	1 << TFW_HTTP_METH_TRACE },
	{ "UNLOCK",	1 << TFW_HTTP_METH_UNLOCK, },
	{ "PURGE",	1 << TFW_HTTP_METH_PURGE },
	{ "unknown",	1 << _TFW_HTTP_METH_UNKNOWN },
	{ 0 }
};

/*
 * Each cache policy directive is put into a separately allocated
 * memory are within a location definition.
 * The directives are deduplicated when put into the array.
 */
#define TFW_CAPOLICY_ARRAY_SZ	(64)

/*
 * Each non-idempotent request definition directive is put into
 * a separately allocated memory area. The pointers to the memory
 * are put into a fixed size array of pointers within a location
 * definition.
 */
#define TFW_NIPDEF_ARRAY_SZ	(64)

/* Max number of headers allowed for end user to modify. */
#define TFW_USRHDRS_ARRAY_SZ	(64)

/*
 * All 'location' directives are put into a fixed size array.
 * Duplicate directives are not allowed.
 */
#define TFW_LOCATION_ARRAY_SZ	(64)

/*
 * IP addresses that make the ACL for cache purge operations are put
 * into a fixed size array. The IP addresses are kept in form of an
 * IPv6 address and the prefix size. sockaddr_in6.sin6_scope_id is
 * used to store the prefix size.
 */
#define TFW_CAPUACL_ARRAY_SZ	(32)

static TfwAddr	tfw_capuacl_dflt[TFW_CAPUACL_ARRAY_SZ];

/*
 * Default vhost is a wildcard vhost. It matches any URI.
 * It may (or may not) contain a set of various directives.
 *
 * Note that @loc_dflt in the default vhost serves as global
 * default caching policy.
 */
static const char s_hdr_via_dflt[] =
	"tempesta_fw" " (" TFW_NAME " " TFW_VERSION ")";

/*
 * Matching functions for match operators. A TfwStr{} is compared
 * with a plain C string according to a specified match operator.
 * The functions are generic.
 */
static bool
__tfw_match_wildcard(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	return ((op == TFW_HTTP_MATCH_O_WILDCARD)
		&& (len == 1) && (*cstr == '*'));
}

static bool
__tfw_match_suffix(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr_off(arg, arg->len - len, cstr, len, flags);
}

static bool
__tfw_match_eq(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr(arg, cstr, len, flags);
}

static bool
__tfw_match_prefix(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr(arg, cstr, len, flags);
}

typedef bool (*__tfw_match_fn)(tfw_match_t, const char *, size_t, TfwStr *);

static const __tfw_match_fn __tfw_match_fn_tbl[] = {
	[0 ... _TFW_HTTP_MATCH_O_COUNT] = NULL,
	[TFW_HTTP_MATCH_O_WILDCARD]	= __tfw_match_wildcard,
	[TFW_HTTP_MATCH_O_EQ]		= __tfw_match_eq,
	[TFW_HTTP_MATCH_O_PREFIX]	= __tfw_match_prefix,
	[TFW_HTTP_MATCH_O_SUFFIX]	= __tfw_match_suffix,
};

/*
 * Find a matching non-idempotent request directive. Strings
 * are compared according to the match operator in the directive.
 * A pointer to the matching TfwNipDef structure is returned if
 * the match is found. NULL is returned if there's no match.
 */
static inline bool
__tfw_nipdef_match_fn(TfwNipDef *nipdef, TfwStr *arg)
{
	__tfw_match_fn match_fn = __tfw_match_fn_tbl[nipdef->op];
	BUG_ON(!match_fn);

	return match_fn(nipdef->op, nipdef->arg, nipdef->len, arg);
}

TfwNipDef *
tfw_nipdef_match(TfwLocation *loc, unsigned char method, TfwStr *arg)
{
	size_t i;

	BUG_ON(!loc);
	BUG_ON(!arg);

	for (i = 0; i < loc->nipdef_sz; ++i) {
		TfwNipDef *nipdef = loc->nipdef[i];
		if ((nipdef->method & (1 << method))
		    && __tfw_nipdef_match_fn(nipdef, arg))
			return nipdef;
	}
	return NULL;
}

/*
 * Find a matching cache policy directive. Strings are compared
 * according to the match operator in the directive. A pointer
 * to the matching TfwCaPolicy structure is returned if the
 * match is found. Null is returned if there's no match.
 *
 * TODO #732 use multi-pattern string matching.
 */
static inline bool
__tfw_capolicy_match_fn(TfwCaPolicy *capo, TfwStr *arg)
{
	__tfw_match_fn match_fn = __tfw_match_fn_tbl[capo->op];
	BUG_ON(!match_fn);

	return match_fn(capo->op, capo->arg, capo->len, arg);
}

TfwCaPolicy *
tfw_capolicy_match(TfwLocation *loc, TfwStr *arg)
{
	size_t i;

	BUG_ON(!loc);
	BUG_ON(!arg);

	for (i = 0; i < loc->capo_sz; ++i) {
		TfwCaPolicy *capo = loc->capo[i];
		if (__tfw_capolicy_match_fn(capo, arg))
			return capo;
	}
	return NULL;
}

/*
 * Find a matching location directive within specified vhost.
 * A pointer to the matching TfwLocation structure is returned
 * if the match is found. NULL is returned if there's no match.
 */
static inline bool
__tfw_location_match(TfwLocation *loc, TfwStr *arg)
{
	__tfw_match_fn match_fn = __tfw_match_fn_tbl[loc->op];
	BUG_ON(!match_fn);

	return match_fn(loc->op, loc->arg, loc->len, arg);
}

TfwLocation *
tfw_location_match(TfwVhost *vhost, TfwStr *arg)
{
	size_t i;

	BUG_ON(!vhost);
	BUG_ON(!arg);

	for (i = 0; i < vhost->loc_sz; ++i) {
		TfwLocation *loc = &vhost->loc[i];
		if (__tfw_location_match(loc, arg))
			return loc;
	}

	return NULL;
}

/*
 * Find request's location with server group linked. If there is no
 * separate location for request (or there is no server group linked
 * with such location), then get the default location of the request's
 * current vhost (must be present in any case).
 */
static inline TfwLocation *
tfw_vhost_act_location(TfwHttpReq *req)
{
	TfwLocation *loc = req->location;
	TfwVhost *vhost = req->vhost;

	BUG_ON(!vhost);
	if (loc && loc->main_sg)
		return loc;

	return vhost->loc_dflt;
}

/*
 * Search server connection in main or backup server groups in
 * locations of the request's current vhost.
 */
TfwSrvConn *
tfw_vhost_get_srv_conn(TfwMsg *msg)
{
	TfwLocation *loc;
	TfwSrvGroup *main_sg, *backup_sg;
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn = NULL;

	loc = tfw_vhost_act_location(req);
	main_sg = loc->main_sg;
	backup_sg = loc->backup_sg;

	BUG_ON(!main_sg);
	TFW_DBG2("vhost: use server group: '%s'\n", main_sg->name);

	if (likely(main_sg->sched))
		srv_conn = main_sg->sched->sched_sg_conn(msg, main_sg);

	if (unlikely(!srv_conn && backup_sg && backup_sg->sched)) {
		TFW_DBG("vhost: the main group is offline, use backup: '%s'\n",
			backup_sg->name);
		srv_conn = backup_sg->sched->sched_sg_conn(msg, backup_sg);
	}

	if (unlikely(!srv_conn))
		TFW_DBG2("vhost: Unable to select server from group '%s'\n",
			 backup_sg ? backup_sg->name : main_sg->name);

	return srv_conn;
}

/**
 * Find a headers modification description according to target message type
 * and current location.
 *
 * @loc		- request URI location;
 * @vhost	- virtual host for the request;
 * @mod_type	- Target modification type, TFW_VHOST_HDRMOD_(REQ|RESP).
 */
TfwHdrMods*
tfw_vhost_get_hdr_mods(TfwLocation *loc, TfwVhost *vhost, int mod_type)
{
	TfwVhost *vh_dflt = vhost->vhost_dflt;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		loc = vhost->loc_dflt;
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		loc = vh_dflt ? vh_dflt->loc_dflt : NULL;
	if (!loc)
		return NULL;

	return &loc->mod_hdrs[mod_type];
}

/*
 * Configuration processing.
 */

/*
 * Pointer to the current location structure.
 * The pointer is shared among multiple functions below.
 */
static TfwLocation *tfwcfg_this_location;
/* Entry for configuration of separate vhost. */
static TfwVhost		*tfw_vhost_entry;
/* Pointer to all current vhosts. */
static TfwVhostList	*tfw_vhosts;
/* Pointer to all vhosts parsed during reconfiguration. */
static TfwVhostList	*tfw_vhosts_reconfig;
/* Object with global level settings (non-reconfigurable). */
static TfwGlobal	tfw_global = {
	.hdr_via	= s_hdr_via_dflt,
	.hdr_via_len	= sizeof(s_hdr_via_dflt) - 1,
	.capuacl	= tfw_capuacl_dflt,
};

/*
 * Get vhost matching the specified name. Vhost's reference counter
 * is incremented in case of successful search.
 */
TfwVhost *
tfw_vhost_lookup(const char *name)
{
	TfwVhost *vhost;

	list_for_each_entry(vhost, &tfw_vhosts_reconfig->head, list) {
		if (!strcasecmp(vhost->name, name)) {
			tfw_vhost_get(vhost);
			return vhost;
		}
	}
	return NULL;
}

TfwGlobal *
tfw_vhost_get_global(void)
{
	return &tfw_global;
}

static inline bool
tfw_vhost_default(TfwVhost *vhost)
{
	return tfw_vhosts_reconfig->vhost_dflt == vhost;
}

/*
 * Match the IP address @addr against the addresses in the ACL list.
 * The addresses are compared according to the prefix length stored
 * with each address in the ACL list.
 * True is returned if the match is found.
 * False is returned otherwise.
 */
bool
tfw_capuacl_match(TfwAddr *addr)
{
	size_t i;
	struct in6_addr *inaddr = &addr->sin6_addr;

	for (i = 0; i < tfw_global.capuacl_sz; ++i) {
		TfwAddr *acl_addr = &tfw_global.capuacl[i];
		if (ipv6_prefix_equal(inaddr, &acl_addr->sin6_addr,
					      acl_addr->in6_prefix))
			return true;
	}
	return false;
}

/*
 * Find a non-idempotent request definition entry within specified location.
 * Entries are processed in the order they are defined in the configuration.
 * That means the matching entry must be the last entry in the array, and it
 * must have the same match @op and the same @arg.
 */
static TfwNipDef *
tfw_nipdef_lookup(TfwLocation *loc, int op, const char *arg, size_t len)
{
	TfwNipDef *nipdef;

	if (!loc->nipdef_sz)
		return NULL;

	nipdef = loc->nipdef[loc->nipdef_sz - 1];
	if ((nipdef->op == op) && (nipdef->len == len)
	    && !strcasecmp(nipdef->arg, arg))
		return nipdef;

	return NULL;
}

static TfwNipDef *
tfw_nipdef_lookup_dup(TfwLocation *loc, int method,
		      int op, const char *arg, size_t len)
{
	size_t i;
	TfwNipDef *nipdef;

	if (!loc->nipdef_sz)
		return NULL;

	/* Check all entries but the last one. */
	for (i = 0; i < loc->nipdef_sz - 1; ++i) {
		nipdef = loc->nipdef[i];
		if ((nipdef->op == op) && (nipdef->len == len)
		    && !strcasecmp(nipdef->arg, arg))
			return nipdef;
	}
	/* Check the last entry. */
	nipdef = loc->nipdef[i];
	if ((nipdef->method & method) && (nipdef->op == op)
	    && (nipdef->len == len) && !strcasecmp(nipdef->arg, arg))
		return nipdef;

	return NULL;
}

/*
 * Create and initialize a new non-idempotent request definition entry,
 * and add it to the given location structure. The entry is added as
 * a pointer to the memory allocated to hold the definition.
 */
static TfwNipDef *
tfw_nipdef_addnew(TfwLocation *loc, int method,
		  int op, const char *arg, size_t len)
{
	char *data;
	TfwNipDef *nipdef;

	if (loc->nipdef_sz == TFW_NIPDEF_ARRAY_SZ)
		return NULL;

	if ((data = kmalloc(sizeof(TfwNipDef) + len + 1, GFP_KERNEL)) == NULL)
		return NULL;

	nipdef = (TfwNipDef *)data;
	nipdef->method = method;
	nipdef->op = op;
	nipdef->arg = data + sizeof(TfwNipDef);
	nipdef->len = len;
	memcpy((void *)nipdef->arg, (void *)arg, len + 1);

	loc->nipdef[loc->nipdef_sz++] = nipdef;

	return nipdef;
}

static int
tfw_cfgop_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
	size_t len;
	int ret, method, op;
	const char *in_method, *in_op, *arg;
	TfwNipDef *nipdef;
	TfwVhost *vh_dflt;

	BUILD_BUG_ON(sizeof(tfw_method_enum[0].value) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 3) {
		TFW_ERR_NL("%s: Invalid number of arguments.\n", cs->name);
		return -EINVAL;
	}

	/* The method: one of GET, PUT, POST, etc. in form of a bitmask. */
	in_method = ce->vals[0];
	ret = tfw_cfg_map_enum(tfw_method_enum, in_method, &method);
	if (ret) {
		TFW_ERR_NL("Unsupported HTTP method: '%s %s'\n",
			   cs->name, in_method);
		return -EINVAL;
	}

	/* The match operator. */
	in_op = ce->vals[1];
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR_NL("Unsupported match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* The match string. */
	arg = ce->vals[2];
	len = strlen(arg);

	/*
	 * Issue a warning if there's an entry with the same argument
	 * (URI path) that is not the last entry.
	 */
	vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	if (tfw_nipdef_lookup_dup(loc, method, op, arg, len))
		TFW_WARN_NL("%s: Duplicate entry in location '%s': "
			    "'%s %s %s %s'\n", cs->name,
			    loc == vh_dflt->loc_dflt ? "default" : loc->arg,
			    cs->name, in_method, in_op, arg);

	/*
	 * Do not add a "duplicate" entry within a location. If the
	 * preceding entry has the same @op and @arg, then just add
	 * the new method to the entry.
	 */
	nipdef = tfw_nipdef_lookup(loc, op, arg, len);
	if (nipdef) {
		nipdef->method |= method;
	} else {
		nipdef = tfw_nipdef_addnew(loc, method, op, arg, len);
		if (nipdef == NULL)
			return -ENOMEM;
	}

	return 0;
}

static int
tfw_cfgop_loc_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_nonidempotent(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_in_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_nonidempotent(cs, ce, tfw_vhost_entry->loc_dflt);
}

static int
tfw_cfgop_out_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_nonidempotent(cs, ce, vh_dflt->loc_dflt);
}

static int
tfw_cfgop_mod_hdr_add(TfwLocation *loc, const char *name, const char *value,
		      int mod_type, bool append)
{
	TfwStr *hdr;
	TfwHdrMods *h_mods = &loc->mod_hdrs[mod_type];
	TfwHdrModsDesc *desc = &h_mods->hdrs[h_mods->sz];

	if (h_mods->sz == TFW_USRHDRS_ARRAY_SZ) {
		TFW_WARN_NL("Too lot of custom headers, %d supported.\n",
			    TFW_USRHDRS_ARRAY_SZ);
		return -EINVAL;
	}
	if (!(hdr = tfw_http_msg_make_hdr(loc->hdrs_pool, name, value))) {
		TFW_WARN_NL("Can't create header.\n");
		return -ENOMEM;
	}
	desc->hdr = hdr;
	desc->append = append;
	desc->hid = (mod_type == TFW_VHOST_HDRMOD_RESP)
			? tfw_http_msg_resp_spec_hid(hdr)
			: tfw_http_msg_req_spec_hid(hdr);
	++h_mods->sz;

	return 0;
}

/**
 * Parse '[req|resp]_hdr_[add|set] directives. @append is set to true for 'add'.
 * @msg_type is responsible for req or resp.
 * Both directives has two parameters: header name and it's value. Value
 * is optional for 'set' directive.
 */
static int
tfw_cfgop_mod_hdr(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc,
		  int mod_type, bool append)
{
	const char *name;
	const char *value = NULL;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	switch (ce->val_n)
	{
	case 2:
		break;
	case 1:
		if (!append)
			break;
		/* Fall through */
	default:
		TFW_ERR_NL("%s: Invalid number of values.\n", cs->name);
		return -EINVAL;
	}

	name = ce->vals[0];
	if (ce->val_n == 2)
		value = ce->vals[1];

	return tfw_cfgop_mod_hdr_add(loc, name, value, mod_type, append);
}

static int
tfw_cfgop_loc_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_REQ, true);
}

static int
tfw_cfgop_loc_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_REQ, false);
}

static int
tfw_cfgop_in_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, true);
}

static int
tfw_cfgop_in_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, false);
}

static int
tfw_cfgop_out_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, true);
}

static int
tfw_cfgop_out_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, false);
}

static int
tfw_cfgop_loc_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_RESP, true);
}

static int
tfw_cfgop_loc_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_RESP, false);
}

static int
tfw_cfgop_in_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, true);
}

static int
tfw_cfgop_in_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, false);
}

static int
tfw_cfgop_out_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, true);
}

static int
tfw_cfgop_out_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, false);
}

/*
 * Find a cache policy directive entry.
 */
static TfwCaPolicy *
tfw_capolicy_lookup(TfwLocation *loc, int cmd, int op, const char *arg,
		    size_t len)
{
	size_t i, capo_sz = loc->capo_sz;

	for (i = 0; i < capo_sz; ++i) {
		TfwCaPolicy *capo = loc->capo[i];
		if ((capo->cmd == cmd) && (capo->op == op) && (capo->len == len)
		    && !strncasecmp(capo->arg, arg, len))
			return capo;
	}

	return NULL;
}

/*
 * Create and initialize a new cache policy entry.
 */
static TfwCaPolicy *
tfw_capolicy_new(int cmd, int op, const char *arg, size_t len)
{
	TfwCaPolicy *capo;

	if ((capo = kmalloc(sizeof(TfwCaPolicy) + len + 1, GFP_KERNEL)) == NULL)
		return NULL;

	capo->cmd = cmd;
	capo->op = op;
	capo->arg = (char *)(capo + 1);
	capo->len = len;
	memcpy((void *)capo->arg, (void *)arg, len + 1);

	return capo;
}

/*
 * Process a cache policy directive. The directive is added to the
 * current location structure. Duplicate directives are ignored but
 * a warning is produced in that case. if a directive lists several
 * strings to match, then an identical directive is added for each
 * string that is listed.
 */
static int
tfw_cfgop_capolicy(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc, int cmd)
{
	int ret;
	size_t i, len;
	tfw_match_t op;
	const char *in_op, *arg;

	BUG_ON((cmd != TFW_D_CACHE_BYPASS) && (cmd != TFW_D_CACHE_FULFILL));

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n < 2) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	in_op = ce->vals[0];	/* Match operator. */

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR_NL("Unknown match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* Add each match string in the directive to the array.*/
	for (i = 1; i < ce->val_n; ++i) {
		TfwCaPolicy *capo;

		arg = ce->vals[i];
		len = strlen(arg);

		if (tfw_capolicy_lookup(loc, cmd, op, arg, len)) {
			TFW_WARN_NL("%s: Duplicate entry: '%s %s %s'\n",
				    cs->name, cs->name, in_op, arg);
			continue;
		}
		if (loc->capo_sz == TFW_CAPOLICY_ARRAY_SZ)
			return -ENOMEM;
		if (!(capo = tfw_capolicy_new(cmd, op, arg, len)))
			return -ENOMEM;
		loc->capo[loc->capo_sz++] = capo;
	}

	return 0;
}

/*
 * The configuration parser has recognized the cache policy directive
 * already, so there's no need to spend cycles and convert it again
 * from the string to the enum value. The functions below are for
 * each directive inside the location section, for each directive
 * inside the vhost section (default location for current vhost),
 * and for each directive outside of any vhost section (global
 * default location).
 */
static int
tfw_cfgop_loc_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_capolicy(cs, ce, tfwcfg_this_location,
				  TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_loc_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_capolicy(cs, ce, tfwcfg_this_location,
				  TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_in_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_capolicy(cs, ce, tfw_vhost_entry->loc_dflt,
				  TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_in_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_capolicy(cs, ce, tfw_vhost_entry->loc_dflt,
				  TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_in_http_post_validate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_vhost_entry->loc_dflt->validate_post_req = 1;
	return 0;
}

static int
tfw_cfgop_out_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_capolicy(cs, ce, vh_dflt->loc_dflt,
				  TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_out_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_capolicy(cs, ce, vh_dflt->loc_dflt,
				  TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_out_http_post_validate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_vhosts_reconfig->vhost_dflt->loc_dflt->validate_post_req = 1;
	return 0;
}

/*
 * Find a location directive entry. The entry is looked up
 * in the array that holds all location directives.
 */
static TfwLocation *
tfw_location_lookup(TfwVhost *vhost, tfw_match_t op, const char *arg, size_t len)
{
	size_t i;

	for (i = 0; i < vhost->loc_sz; ++i) {
		TfwLocation *loc = &vhost->loc[i];
		if ((loc->op == op) && (loc->len == len)
		    && !strncasecmp(loc->arg, arg, len))
			return loc;
	}

	return NULL;
}

static int
tfw_location_init(TfwLocation *loc, tfw_match_t op, const char *arg,
		  size_t len, TfwPool *pool)
{
	char *argmem, *data;
	size_t size = sizeof(FrangCfg)
		    + sizeof(TfwCaPolicy *) * TFW_CAPOLICY_ARRAY_SZ
		    + sizeof(TfwNipDef *) * TFW_NIPDEF_ARRAY_SZ
		    + sizeof(TfwHdrModsDesc) * TFW_USRHDRS_ARRAY_SZ * 2;

	if ((argmem = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	if ((data = kzalloc(size, GFP_KERNEL)) == NULL) {
		kfree(argmem);
		return -ENOMEM;
	}

	loc->op = op;
	loc->arg = argmem;
	loc->len = len;
	loc->frang_cfg = (FrangCfg *)data;
	loc->capo = (TfwCaPolicy **)(loc->frang_cfg + 1);
	loc->capo_sz = 0;
	loc->nipdef = (TfwNipDef **)(loc->capo + TFW_CAPOLICY_ARRAY_SZ);
	loc->nipdef_sz = 0;
	loc->hdrs_pool = pool;
	loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].hdrs =
			(TfwHdrModsDesc *)(loc->nipdef + TFW_NIPDEF_ARRAY_SZ);
	loc->mod_hdrs[TFW_VHOST_HDRMOD_RESP].hdrs =
			loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].hdrs + TFW_USRHDRS_ARRAY_SZ;
	memcpy((void *)loc->arg, (void *)arg, len + 1);

	return 0;
}

/*
 * Create and initialize a new entry for a location directive.
 * The entry is placed in the array that holds all location directives
 * for current vhost.
 */
static inline TfwLocation *
tfw_location_new(TfwVhost *vhost, tfw_match_t op, const char *arg, size_t len)
{
	TfwLocation *loc;

	loc = &vhost->loc[vhost->loc_sz];
	if (tfw_location_init(loc, op, arg, len, vhost->hdrs_pool))
		return NULL;
	vhost->loc_sz++;
	return loc;
}

/*
 * Process the location directive that opens a section for cache
 * policy directives in the configuration.
 */
static int
tfw_cfgop_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwVhost *vhost)
{
	int ret;
	size_t len;
	tfw_match_t op;
	const char *in_op, *arg;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 2) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	/* Get the values of the 'location' directive. */
	in_op = ce->vals[0];	/* Match operator. */
	arg = ce->vals[1];	/* String for the match operator. */
	len = strlen(arg);

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR_NL("%s: Unknown match OP: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}

	/* Make sure the location is not a duplicate. */
	if (tfw_location_lookup(vhost, op, arg, len)) {
		TFW_ERR_NL("%s: Duplicate entry: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}


	if (vhost->loc_sz == TFW_LOCATION_ARRAY_SZ) {
		TFW_ERR_NL("%s: There is no empty slots in '%s' vhost to"
			   " add new location: '%s %s %s'\n", cs->name,
			   vhost->name, cs->name, in_op, arg);
		return -EINVAL;
	}

	/* Add new location and set it to be the current one. */
	tfwcfg_this_location = tfw_location_new(vhost, op, arg, len);
	if (!tfwcfg_this_location) {
		TFW_ERR_NL("%s: Unable to create new location: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -ENOMEM;
	}

	return 0;
}

static int
tfw_cfgop_in_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	BUG_ON(tfwcfg_this_location);
	return tfw_cfgop_location_begin(cs, ce, tfw_vhost_entry);
}

static int
tfw_cfgop_out_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tfw_vhost_entry);
	BUG_ON(tfwcfg_this_location);
	return tfw_cfgop_location_begin(cs, ce,
					tfw_vhosts_reconfig->vhost_dflt);
}

/*
 * Close the section for a location directive inside of current vhost.
 */
static int
tfw_cfgop_in_location_finish(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_vhost_entry);
	BUG_ON(!tfwcfg_this_location);
	if (!tfw_vhost_default(tfw_vhost_entry)
	    && !tfwcfg_this_location->main_sg)
	{
		TFW_ERR_NL("Directive 'proxy_pass' is not specified for"
			   " location (with arg '%s') inside not default"
			   " vhost '%s'.\n", tfwcfg_this_location->arg,
			   tfw_vhost_entry->name);
		return -EINVAL;
	}
	tfwcfg_this_location = NULL;
	return 0;
}

/*
 * Close the section for a global location directive.
 */
static int
tfw_cfgop_out_location_finish(TfwCfgSpec *cs)
{
	BUG_ON(tfw_vhost_entry);
	BUG_ON(!tfwcfg_this_location);
	tfwcfg_this_location = NULL;
	return 0;
}

/*
 * Free 'location' memory which has been allocated while processing
 * configuration directives.
 */
static void
tfw_location_del(TfwLocation *loc)
{
	size_t i;

	if (unlikely(!loc))
		return;

	for (i = 0; i < loc->capo_sz; ++i) {
		BUG_ON(!loc->capo[i]);
		kfree(loc->capo[i]);
	}
	for (i = 0; i < loc->nipdef_sz; ++i) {
		BUG_ON(!loc->nipdef[i]);
		kfree(loc->nipdef[i]);
	}

	kfree(loc->frang_cfg->http_ct_vals);
	kfree(loc->frang_cfg->http_resp_code_block);

	/*
	 * Free loc->arg and loc->frang_cfg, loc->capo,
	 * loc->nipdef and loc->mod_hdrs.
	 */
	kfree(loc->arg);
	kfree(loc->frang_cfg);

	tfw_sg_put(loc->main_sg);
	tfw_sg_put(loc->backup_sg);
}

/*
 *  Match the ip address against the ACL list.
 */
static bool
tfw_capuacl_lookup(TfwAddr *addr)
{
	size_t i;
	struct in6_addr *inaddr = &addr->sin6_addr;

	for (i = 0; i < tfw_global.capuacl_sz; ++i) {
		struct in6_addr *acl_inaddr = &tfw_global.capuacl[i].sin6_addr;
		if (ipv6_prefix_equal(inaddr, acl_inaddr, addr->in6_prefix))
			return true;
	}
	return false;
}

/*
 * Process the cache_purge_acl directive.
 */
static int
tfw_cfgop_cache_purge_acl(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	const char *val;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			cs->name);
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		TfwAddr addr = { 0 };

		if (tfw_addr_pton_cidr(val, &addr)) {
			TFW_ERR_NL("%s: Invalid ACL entry: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		/* Make sure the address is not a duplicate. */
		if (tfw_capuacl_lookup(&addr)) {
			TFW_ERR_NL("%s: Duplicate IP address or prefix: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		/* Add new ACL entry. */
		if (tfw_global.capuacl_sz == TFW_CAPUACL_ARRAY_SZ) {
			TFW_ERR_NL("%s: Unable to add new ACL: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		tfw_global.capuacl[tfw_global.capuacl_sz++] = addr;
	}
	tfw_global.cache_purge_acl = 1;

	return 0;
}

/*
 * Process the cache_purge directive.
 */
static int
tfw_cfgop_cache_purge(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	const char *val;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			cs->name);
		return -EINVAL;
	}
	if (!ce->val_n) {
		/* Default value for the cache_purge directive. */
		tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		goto done;
	}
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "invalidate")) {
			tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		} else {
			TFW_ERR_NL("%s: unsupported argument: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
	}
done:
	tfw_global.cache_purge = 1;

	return 0;
}

/*
 * Process hdr_via directive.
 * Default value is preset statically.
 */
static int
tfw_cfgop_hdr_via(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t len;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	/*
	 * If a value is specified in the configuration file, then
	 * the default value is not used, even if the processing of
	 * the specified value results in an error.
	 */
	len = strlen(ce->vals[0]);
	if ((tfw_global.hdr_via = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memcpy((void *)tfw_global.hdr_via, (void *)ce->vals[0], len + 1);
	tfw_global.hdr_via_len = len;

	return 0;
}

static int
tfw_cfgop_vhost_check_flags(TfwSrvGroup *main_sg, TfwSrvGroup *backup_sg)
{
	int r = ((main_sg->flags & TFW_SRV_STICKY_FLAGS) ^
		 (backup_sg->flags & TFW_SRV_STICKY_FLAGS));
	if (r)
		TFW_ERR_NL("vhost: srv_groups '%s' and '%s' must "
			   "have the same sticky sessions settings\n",
			   main_sg->name, backup_sg->name);

	return r;
}

static int
__tfw_cfgop_proxy_pass(const char *main_sg_nm, const char *backup_sg_nm,
		       TfwLocation *loc)
{
	int r;
	TfwSrvGroup *main_sg, *backup_sg = NULL;

	main_sg = tfw_sg_lookup_reconfig(main_sg_nm, strlen(main_sg_nm));
	if (!main_sg) {
		TFW_ERR_NL("proxy_pass: srv_group is not found: '%s'\n",
			   main_sg_nm);
		return -EINVAL;
	}
	if (backup_sg_nm) {
		backup_sg = tfw_sg_lookup_reconfig(backup_sg_nm,
						   strlen(backup_sg_nm));
		if (!backup_sg) {
			TFW_ERR_NL("proxy_pass: backup srv_group is not found:"
				   " '%s'\n", backup_sg_nm);
			r = -EINVAL;
			goto err;
		}

		/* Check main/backup group flags for incompatibilities. */
		if (strcasecmp(main_sg_nm, "default")
		    && strcasecmp(backup_sg_nm, "default")
		    && tfw_cfgop_vhost_check_flags(main_sg, backup_sg))
		{
			r = -EINVAL;
			goto err;
		}
	}

	loc->main_sg = main_sg;
	loc->backup_sg = backup_sg;

	return 0;
err:
	tfw_sg_put(main_sg);
	tfw_sg_put(backup_sg);

	return r;
}

static inline int
tfw_cfgop_proxy_pass(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
	int r;
	const char *in_main_sg, *in_backup_sg;

	if ((r = tfw_cfg_check_val_n(ce, 1)))
		return r;

	in_main_sg = ce->vals[0];
	in_backup_sg = tfw_cfg_get_attr(ce, "backup", NULL);

	if (!tfw_vhost_entry || tfw_vhost_default(tfw_vhost_entry)) {
		if (!strcasecmp(in_main_sg, TFW_VH_DFT_NAME)
		    && (!in_backup_sg
			|| !strcasecmp(in_backup_sg, TFW_VH_DFT_NAME)))
			return 0;
		TFW_ERR_NL("Default vhost must point to default server"
			   " group only, so it is not allowed to specify"
			   " any not default 'proxy_pass' directive inside of"
			   " default vhost.\n");
		return -EINVAL;
	}
	return __tfw_cfgop_proxy_pass(in_main_sg, in_backup_sg, loc);
}

static int
tfw_cfgop_loc_proxy_pass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_proxy_pass(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_in_proxy_pass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_proxy_pass(cs, ce, tfw_vhost_entry->loc_dflt);
}

void
tfw_vhost_destroy(TfwVhost *vhost)
{
	int i;

	for (i = 0; i < vhost->loc_sz; ++i)
		tfw_location_del(&vhost->loc[i]);
	tfw_location_del(vhost->loc_dflt);
	tfw_vhost_put(vhost->vhost_dflt);
	tfw_pool_destroy(vhost->hdrs_pool);
	kfree(vhost);
}

static TfwVhost *
tfw_vhost_create(const char *name)
{
	TfwPool *pool;
	TfwVhost *vhost;
	int name_sz = strlen(name) + 1;
	int size = sizeof(TfwVhost)
		+ name_sz
		+ sizeof(TfwLocation) * (TFW_LOCATION_ARRAY_SZ + 1);

	if (!(pool = __tfw_pool_new(0)))
		return NULL;

	if (!(vhost = kzalloc(size, GFP_KERNEL))) {
		tfw_pool_destroy(pool);
		TFW_ERR_NL("Cannot allocate vhost entry '%s'\n", name);
		return NULL;
	}
	INIT_LIST_HEAD(&vhost->list);
	vhost->name = (char *)(vhost + 1);
	vhost->loc_dflt = (TfwLocation *)(vhost->name + name_sz);
	vhost->loc = (TfwLocation *)(vhost->loc_dflt + 1);
	memcpy((void *)vhost->name, (void *)name, name_sz);
	vhost->hdrs_pool = pool;
	atomic64_set(&vhost->refcnt, 1);

	return vhost;
}

TfwVhost *
tfw_vhost_new(const char *name)
{
	TfwVhost *vhost;

	if (!(vhost = tfw_vhost_create(name)))
		return NULL;

	/* Init default location for the new vhost. */
	if (tfw_location_init(vhost->loc_dflt,
			      TFW_HTTP_MATCH_O_WILDCARD, "*", 1,
			      vhost->hdrs_pool))
	{
		TFW_ERR_NL("Unable to add default location"
			   " for vhost '%s'.\n", name);
		tfw_vhost_destroy(vhost);
		return NULL;
	}

	return vhost;
}

static inline void
tfw_vhost_add(TfwVhost *vhost)
{
	list_add(&vhost->list, &tfw_vhosts_reconfig->head);
	tfw_vhost_get(vhost);
	if (!tfw_vhost_default(vhost)) {
		vhost->vhost_dflt = tfw_vhosts_reconfig->vhost_dflt;
		tfw_vhost_get(vhost->vhost_dflt);
	}
}

/*
 * Frang configuration for global and location-specific settings.
 * Note, global Frang settings are not reconfigurable.
 */

/* Frang global settings object. */
static FrangCfg frang_cfg __read_mostly;

static const TfwCfgEnum frang_http_methods_enum[] = {
	{ "copy",	TFW_HTTP_METH_COPY },
	{ "delete",	TFW_HTTP_METH_DELETE },
	{ "get",	TFW_HTTP_METH_GET },
	{ "head",	TFW_HTTP_METH_HEAD },
	{ "lock",	TFW_HTTP_METH_LOCK },
	{ "mkcol",	TFW_HTTP_METH_MKCOL },
	{ "move",	TFW_HTTP_METH_MOVE },
	{ "options",	TFW_HTTP_METH_OPTIONS },
	{ "patch",	TFW_HTTP_METH_PATCH },
	{ "post",	TFW_HTTP_METH_POST },
	{ "propfind",	TFW_HTTP_METH_PROPFIND },
	{ "proppatch",	TFW_HTTP_METH_PROPPATCH },
	{ "put",	TFW_HTTP_METH_PUT },
	{ "trace",	TFW_HTTP_METH_TRACE },
	{ "unlock",	TFW_HTTP_METH_UNLOCK },
	{ "unknown",	_TFW_HTTP_METH_UNKNOWN }, /* Pass unknown methods. */
	{}
};

/* Return Frang global configuration settings. */
FrangCfg *
tfw_vhost_global_frang_cfg(void)
{
	return &frang_cfg;
}

static int
tfw_cfgop_frang_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce,
			     unsigned long *cfg_methods_mask)
{
	int i, r, method_id;
	const char *method_str;
	unsigned long methods_mask = 0;

	BUILD_BUG_ON(sizeof(*cfg_methods_mask) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, method_str) {
		r = tfw_cfg_map_enum(frang_http_methods_enum, method_str,
				     &method_id);
		if (r) {
			TFW_ERR_NL("frang: invalid method: '%s'\n", method_str);
			return -EINVAL;
		}

		TFW_DBG3("frang: parsed method: %s => %d\n",
			 method_str, method_id);
		methods_mask |= (1UL << method_id);
	}

	TFW_DBG3("parsed methods_mask: %#lx\n", methods_mask);
	*cfg_methods_mask = methods_mask;
	return 0;
}

static int
tfw_cfgop_frang_http_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce, FrangCfg *conf)
{
	void *mem;
	const char *in_str;
	char *strs, *strs_pos;
	FrangCtVal *vals, *vals_pos;
	size_t i, strs_size, vals_n, vals_size;

	/* Allocate a single chunk of memory which is suitable to hold the
	 * variable-sized list of variable-sized strings.
	 *
	 * Basically that will look like:
	 *  [[FrangCtVal, FrangCtVal, FrangCtVal, NULL]str1\0\str2\0\str3\0]
	 *           +         +         +             ^      ^      ^
	 *           |         |         |             |      |      |
	 *           +---------------------------------+      |      |
	 *                     |         |                    |      |
	 *                     +------------------------------+      |
	 *                               |                           |
	 *                               +---------------------------+
	 */
	vals_n = ce->val_n;
	vals_size = sizeof(FrangCtVal) * (vals_n + 1);
	strs_size = 0;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		strs_size += strlen(in_str) + 1;
	}
	mem = kzalloc(vals_size + strs_size, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	vals = mem;
	strs = mem + vals_size;

	/* Copy tokens to the new vals/strs list. */
	/* TODO: validate tokens, they should look like: "text/plain". */
	vals_pos = vals;
	strs_pos = strs;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		size_t len = strlen(in_str) + 1;

		memcpy(strs_pos, in_str, len);
		vals_pos->str = strs_pos;
		vals_pos->len = (len - 1);

		TFW_DBG3("parsed Content-Type value: '%s'\n", in_str);

		vals_pos++;
		strs_pos += len;
	}
	BUG_ON(vals_pos != (vals + vals_n));
	BUG_ON(strs_pos != (strs + strs_size));

	conf->http_ct_vals = vals;
	return 0;
}

static int
frang_parse_ushort(const char *s, unsigned short *out)
{
	int n, r;

	if ((r = tfw_cfg_parse_int(s, &n)))
		return r;
	if ((r = tfw_cfg_check_range(n, 1, USHRT_MAX)))
		return r;
	*out = n;

	return 0;
}

/**
 * Save response code block configuration
 */
static int
tfw_cfgop_frang_rsp_code_block(TfwCfgSpec *cs, TfwCfgEntry *ce, FrangCfg *conf)
{
	FrangHttpRespCodeBlock *cb;
	static const char *error_msg_begin = "frang: http_resp_code_block:";
	int n, i;

	if (ce->attr_n) {
		TFW_ERR_NL("%s arguments may not have the \'=\' sign\n",
			   error_msg_begin);
		return -EINVAL;
	}

	if (ce->val_n < 3) {
		TFW_ERR_NL("%s too few arguments\n", error_msg_begin);
		return -EINVAL;
	}

	cb = kzalloc(sizeof(FrangHttpRespCodeBlock), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	conf->http_resp_code_block = cb;

	i = ce->val_n - 2;
	while (--i >= 0) {
		if (tfw_cfg_parse_int(ce->vals[i], &n)
		    || !tfw_http_resp_code_range(n)) {
			TFW_ERR_NL("%s invalid HTTP code \"%s\"",
				   error_msg_begin, ce->vals[i]);
			return -EINVAL;
		}
		/* Atomic restriction isn't needed here */
		__set_bit(HTTP_CODE_BIT_NUM(n), cb->codes);
	}

	if (frang_parse_ushort(ce->vals[ce->val_n - 2], &cb->limit)
	    || frang_parse_ushort(ce->vals[ce->val_n - 1], &cb->tf))
		return -EINVAL;

	return 0;
}

static int
tfw_cfgop_frang_loc_req_rate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->req_rate;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_req_burst(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->req_burst;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_hdr_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->clnt_hdr_timeout;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_body_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->clnt_body_timeout;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_uri_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_uri_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_field_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_field_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_body_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_body_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_hdr_cnt(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_hdr_cnt;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_hdr_chunk_cnt(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_hchunk_cnt;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_body_chunk_cnt(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_bchunk_cnt;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_host_required(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_host_required;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_ct_required(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	BUG_ON(!tfwcfg_this_location);
	cs->dest = &tfwcfg_this_location->frang_cfg->http_ct_required;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_loc_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned long *methods_mask;

	BUG_ON(!tfwcfg_this_location);
	methods_mask = &tfwcfg_this_location->frang_cfg->http_methods_mask;
	return tfw_cfgop_frang_http_methods(cs, ce, methods_mask);
}

static int
tfw_cfgop_frang_out_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_frang_http_methods(cs, ce,
					    &frang_cfg.http_methods_mask);
}

static int
tfw_cfgop_frang_loc_http_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_frang_http_ct_vals(cs, ce,
					    tfwcfg_this_location->frang_cfg);
}

static int
tfw_cfgop_frang_out_http_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_frang_http_ct_vals(cs, ce, &frang_cfg);
}

static int
tfw_cfgop_http_post_validate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfwcfg_this_location->validate_post_req = 1;
	return 0;
}

static int
tfw_cfgop_frang_loc_rsp_code_block(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_frang_rsp_code_block(cs, ce,
					      tfwcfg_this_location->frang_cfg);
}

static int
tfw_cfgop_frang_out_rsp_code_block(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_frang_rsp_code_block(cs, ce, &frang_cfg);
}

static int
tfw_vhost_cfgstart(void)
{
	TfwVhost *vh_dflt;

	BUG_ON(tfw_vhosts_reconfig);
	tfw_vhosts_reconfig = kmalloc(sizeof(TfwVhostList), GFP_KERNEL);
	if (!tfw_vhosts_reconfig) {
		TFW_ERR_NL("Unable to allocate vhosts' list.\n");
		return -ENOMEM;
	}

	tfw_vhosts_reconfig->expl_dflt = false;
	INIT_LIST_HEAD(&tfw_vhosts_reconfig->head);
	if(!(vh_dflt = tfw_vhost_new(TFW_VH_DFT_NAME))) {
		TFW_ERR_NL("Unable to create default vhost.\n");
		return -ENOMEM;
	}

	tfw_vhosts_reconfig->vhost_dflt = vh_dflt;

	return 0;
}

static int
tfw_vhost_cfgend(void)
{
	TfwSrvGroup *sg_def;
	TfwVhost *vh_dflt;

	/*
	 * Add default vhost into list if it hadn't been added
	 * yet explicitly and if there is default server group
	 * (explicit or implicit).
	 */
	if (tfw_vhosts_reconfig->expl_dflt)
		return 0;

	sg_def = tfw_sg_lookup_reconfig(TFW_VH_DFT_NAME, sizeof("default") - 1);
	if (!sg_def)
		return 0;

	vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	vh_dflt->loc_dflt->main_sg = sg_def;
	tfw_vhost_add(vh_dflt);

	if (tfw_global.cache_purge && !tfw_global.cache_purge_acl)
		TFW_WARN_NL("Directives mismatching: cache_purge directive"
			    " works only in combination with cache_purge_acl"
			    " directive.\n");
	return 0;
}

static int
tfw_cfgop_vhost_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vhost;

	BUG_ON(tfw_vhost_entry);

	if (tfw_cfg_check_val_n(ce, 1))
		return -EINVAL;
	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}
	list_for_each_entry(vhost, &tfw_vhosts_reconfig->head, list) {
		if (!strcasecmp(vhost->name, ce->vals[0])) {
			TFW_ERR_NL("Duplicate vhost entry: '%s'\n",
				   ce->vals[0]);
			return -EINVAL;
		}
	}
	if (!strcasecmp(ce->vals[0], TFW_VH_DFT_NAME)) {
		tfw_vhosts_reconfig->expl_dflt = true;
		tfw_vhost_entry = tfw_vhosts_reconfig->vhost_dflt;
		if (__tfw_cfgop_proxy_pass(TFW_VH_DFT_NAME, NULL,
					   tfw_vhost_entry->loc_dflt))
			return -EINVAL;
	} else {
		if (!(tfw_vhost_entry = tfw_vhost_new(ce->vals[0]))) {
			TFW_ERR_NL("Unable to create new vhost entry: '%s'\n",
				   ce->vals[0]);
			return -ENOMEM;
		}
	}
	tfw_vhost_add(tfw_vhost_entry);
	if (!tfw_vhost_default(tfw_vhost_entry))
		tfw_vhost_put(tfw_vhost_entry);

	return 0;
}

static int
tfw_cfgop_vhost_finish(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_vhost_entry);
	if (!tfw_vhost_entry->loc_dflt->main_sg) {
		BUG_ON(tfw_vhost_default(tfw_vhost_entry));
		TFW_ERR_NL("Directive 'proxy_pass' is not specified"
			   " for not default vhost '%s'.\n",
			   tfw_vhost_entry->name);
		return -EINVAL;
	}
	tfw_vhost_entry = NULL;
	return 0;
}

static void
tfw_cfgop_vhosts_list_free(TfwVhostList *vhosts)
{
	TfwVhost *tmp, *vhost;

	if (!vhosts)
		return;

	list_for_each_entry_safe(vhost, tmp, &vhosts->head, list) {
		list_del(&vhost->list);
		tfw_vhost_put(vhost);
	}
	tfw_vhost_put(vhosts->vhost_dflt);
	kfree(vhosts);
}

static int
tfw_vhost_start(void)
{
	if (!tfw_runstate_is_reconfig()) {
		/* Convert Frang global timeouts to jiffies for convenience */
		frang_cfg.clnt_hdr_timeout =
			*(unsigned int *)&frang_cfg.clnt_hdr_timeout *
			(unsigned long)HZ;
		frang_cfg.clnt_body_timeout =
			*(unsigned int *)&frang_cfg.clnt_body_timeout *
			(unsigned long)HZ;
	}

	tfw_cfgop_vhosts_list_free(tfw_vhosts);
	tfw_vhosts = tfw_vhosts_reconfig;
	tfw_vhosts_reconfig = NULL;

	return 0;
}

static void
__tfw_cfgop_vhosts_cleanup(void)
{
	tfw_cfgop_vhosts_list_free(tfw_vhosts_reconfig);
	tfw_vhosts_reconfig = NULL;

	if (!tfw_runstate_is_reconfig()) {
		tfw_cfgop_vhosts_list_free(tfw_vhosts);
		tfw_vhosts = NULL;
	}
}

static void
tfw_cfgop_vhosts_cleanup(TfwCfgSpec *cs)
{
	__tfw_cfgop_vhosts_cleanup();
}

static void
tfw_vhost_cfgclean(void)
{
	__tfw_cfgop_vhosts_cleanup();

	if (tfw_runstate_is_reconfig())
		return;

	kfree(frang_cfg.http_ct_vals);
	kfree(frang_cfg.http_resp_code_block);
	memset(&frang_cfg, 0, sizeof(frang_cfg));

	tfw_global.capuacl_sz =
	tfw_global.cache_purge =
	tfw_global.cache_purge_mode =
	tfw_global.cache_purge_acl = 0;

	if (tfw_global.hdr_via && (tfw_global.hdr_via != s_hdr_via_dflt))
		kfree(tfw_global.hdr_via);
	tfw_global.hdr_via = s_hdr_via_dflt;
}

static TfwCfgSpec tfw_vhost_location_specs[] = {
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_nonidempotent,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_req_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_req_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_resp_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_resp_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "request_rate",
		.handler = tfw_cfgop_frang_loc_req_rate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "request_burst",
		.handler = tfw_cfgop_frang_loc_req_burst,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "client_header_timeout",
		.handler = tfw_cfgop_frang_loc_hdr_timeout,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "client_body_timeout",
		.handler = tfw_cfgop_frang_loc_body_timeout,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_uri_len",
		.handler = tfw_cfgop_frang_loc_uri_len,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_field_len",
		.handler = tfw_cfgop_frang_loc_field_len,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_body_len",
		.handler = tfw_cfgop_frang_loc_body_len,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_header_cnt",
		.handler = tfw_cfgop_frang_loc_hdr_cnt,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_header_chunk_cnt",
		.handler = tfw_cfgop_frang_loc_hdr_chunk_cnt,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_body_chunk_cnt",
		.handler = tfw_cfgop_frang_loc_body_chunk_cnt,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_host_required",
		.handler = tfw_cfgop_frang_loc_host_required,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_required",
		.handler = tfw_cfgop_frang_loc_ct_required,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_methods",
		.handler = tfw_cfgop_frang_loc_http_methods,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_vals",
		.handler = tfw_cfgop_frang_loc_http_ct_vals,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_post_validate",
		.handler = tfw_cfgop_http_post_validate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_resp_code_block",
		.handler = tfw_cfgop_frang_loc_rsp_code_block,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "proxy_pass",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_proxy_pass,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_internal_specs[] = {
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_post_validate",
		.deflt = NULL,
		.handler = tfw_cfgop_in_http_post_validate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_in_nonidempotent,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_in_req_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_in_req_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_in_resp_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_in_resp_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "proxy_pass",
		.deflt = NULL,
		.handler = tfw_cfgop_in_proxy_pass,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "location",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfg_cleanup_children,
		.dest = tfw_vhost_location_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_in_location_begin,
			.finish_hook = tfw_cfgop_in_location_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_frang_limits_specs[] = {
	{
		.name = "ip_block",
		.deflt = "off",
		.handler = tfw_cfg_set_bool,
		.dest = &frang_cfg.ip_block,
	},
	{
		.name = "request_rate",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.req_rate,
	},
	{
		.name = "request_burst",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.req_burst,
	},
	{
		.name = "connection_rate",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.conn_rate,
	},
	{
		.name = "connection_burst",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.conn_burst,
	},
	{
		.name = "concurrent_connections",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.conn_max,
	},
	{
		.name = "client_header_timeout",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = (unsigned int *)&frang_cfg.clnt_hdr_timeout,
	},
	{
		.name = "client_body_timeout",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = (unsigned int *)&frang_cfg.clnt_body_timeout,
	},
	{
		.name = "http_uri_len",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.http_uri_len,
	},
	{
		.name = "http_field_len",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.http_field_len,
	},
	{
		.name = "http_body_len",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.http_body_len,
	},
	{
		.name = "http_header_cnt",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.http_hdr_cnt,
	},
	{
		.name = "http_header_chunk_cnt",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.http_hchunk_cnt,
	},
	{
		.name = "http_body_chunk_cnt",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &frang_cfg.http_bchunk_cnt,
	},
	{
		.name = "http_host_required",
		.deflt = "true",
		.handler = tfw_cfg_set_bool,
		.dest = &frang_cfg.http_host_required,
	},
	{
		.name = "http_ct_required",
		.deflt = "false",
		.handler = tfw_cfg_set_bool,
		.dest = &frang_cfg.http_ct_required,
	},
	{
		.name = "http_methods",
		.deflt = "",
		.handler = tfw_cfgop_frang_out_http_methods,
	},
	{
		.name = "http_ct_vals",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_out_http_ct_vals,
		.allow_none = true,
	},
	{
		.name = "http_resp_code_block",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_out_rsp_code_block,
		.allow_none = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_specs[] = {
	{
		.name = "hdr_via",
		.deflt = NULL,
		.handler = tfw_cfgop_hdr_via,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{
		.name = "cache_purge",
		.deflt = NULL,
		.handler = tfw_cfgop_cache_purge,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{
		.name = "cache_purge_acl",
		.deflt = NULL,
		.handler = tfw_cfgop_cache_purge_acl,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_post_validate",
		.deflt = NULL,
		.handler = tfw_cfgop_out_http_post_validate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_out_nonidempotent,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_out_req_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_out_req_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_out_resp_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_out_resp_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "location",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfg_cleanup_children,
		.dest = tfw_vhost_location_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_out_location_begin,
			.finish_hook = tfw_cfgop_out_location_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "vhost",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_vhosts_cleanup,
		.dest = tfw_vhost_internal_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_vhost_begin,
			.finish_hook = tfw_cfgop_vhost_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "frang_limits",
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfg_cleanup_children,
		.dest = tfw_vhost_frang_limits_specs,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{ 0 }
};

TfwMod tfw_vhost_mod = {
	.name		= "vhost",
	.cfgstart	= tfw_vhost_cfgstart,
	.cfgend		= tfw_vhost_cfgend,
	.start		= tfw_vhost_start,
	.specs		= tfw_vhost_specs,
	.cfgclean	= tfw_vhost_cfgclean,
};

int
tfw_vhost_init(void)
{
	tfw_mod_register(&tfw_vhost_mod);
	return 0;
}

void
tfw_vhost_exit(void)
{
	tfw_mod_unregister(&tfw_vhost_mod);
}
