/*
 * rpcd - UBUS RPC server - ucode plugin
 *
 *   Copyright (C) 2021 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include <libubus.h>

#include <ucode/compiler.h>
#include <ucode/lib.h>
#include <ucode/vm.h>

#include <rpcd/plugin.h>

#define RPC_UCSCRIPT_DIRECTORY INSTALL_PREFIX "/share/rpcd/ucode"

static struct blob_buf buf;
static int request_timeout;

/*
 * Track script instances and registered ubus objects in these lists.
 *
 * This is primarily done to make Valgrind happy and to mark the
 * related memory as reachable. Since we don't have a teardown
 * mechanism in rpcd plugins we can't orderly free the related
 * ubus object and ucode VM memory anyway.
 */
static LIST_HEAD(scripts);
static LIST_HEAD(uuobjs);

typedef struct {
	struct list_head list;
	uc_vm_t vm;
	uc_resource_type_t *requesttype;
	uc_value_t *pending_replies;
	char *path;
} rpc_ucode_script_t;

typedef struct {
	struct list_head list;
	rpc_ucode_script_t *script;
	uc_value_t *signature;
	struct ubus_object ubusobj;
} rpc_ucode_ubus_obj_t;

typedef struct {
	struct ubus_context *ubus;
	struct ubus_request_data req;
	struct uloop_timeout timeout;
	rpc_ucode_script_t *script;
	uc_value_t *func;
	uc_value_t *args;
	uc_value_t *info;
	bool replied;
} rpc_ucode_call_ctx_t;

static uc_parse_config_t config = {
	.strict_declarations = false,
	.lstrip_blocks = true,
	.trim_blocks = true,
	.raw_mode = true
};


static rpc_ucode_script_t *
rpc_ucode_obj_to_script(struct ubus_object *obj)
{
	rpc_ucode_ubus_obj_t *uo = container_of(obj, rpc_ucode_ubus_obj_t, ubusobj);

	return uo->script;
}

static uc_value_t *
rpc_ucode_obj_to_signature(struct ubus_object *obj)
{
	rpc_ucode_ubus_obj_t *uo = container_of(obj, rpc_ucode_ubus_obj_t, ubusobj);

	return uo->signature;
}

static void
rpc_ucode_ucv_array_to_blob(uc_value_t *val, struct blob_buf *blob);

static void
rpc_ucode_ucv_object_to_blob(uc_value_t *val, struct blob_buf *blob);

static void
rpc_ucode_ucv_to_blob(const char *name, uc_value_t *val, struct blob_buf *blob)
{
	int64_t n;
	void *c;

	switch (ucv_type(val)) {
	case UC_NULL:
		blobmsg_add_field(blob, BLOBMSG_TYPE_UNSPEC, name, NULL, 0);
		break;

	case UC_BOOLEAN:
		blobmsg_add_u8(blob, name, ucv_boolean_get(val));
		break;

	case UC_INTEGER:
		n = ucv_int64_get(val);

		if (errno == ERANGE)
			blobmsg_add_u64(blob, name, ucv_uint64_get(val));
		else if (n >= INT32_MIN && n <= INT32_MAX)
			blobmsg_add_u32(blob, name, n);
		else
			blobmsg_add_u64(blob, name, n);

		break;

	case UC_DOUBLE:
		blobmsg_add_double(blob, name, ucv_double_get(val));
		break;

	case UC_STRING:
		blobmsg_add_string(blob, name, ucv_string_get(val));
		break;

	case UC_ARRAY:
		c = blobmsg_open_array(blob, name);
		rpc_ucode_ucv_array_to_blob(val, blob);
		blobmsg_close_array(blob, c);
		break;

	case UC_OBJECT:
		c = blobmsg_open_table(blob, name);
		rpc_ucode_ucv_object_to_blob(val, blob);
		blobmsg_close_table(blob, c);
		break;

	default:
		break;
	}
}

static void
rpc_ucode_ucv_array_to_blob(uc_value_t *val, struct blob_buf *blob)
{
	size_t i;

	for (i = 0; i < ucv_array_length(val); i++)
		rpc_ucode_ucv_to_blob(NULL, ucv_array_get(val, i), blob);
}

static void
rpc_ucode_ucv_object_to_blob(uc_value_t *val, struct blob_buf *blob)
{
	ucv_object_foreach(val, k, v)
		rpc_ucode_ucv_to_blob(k, v, blob);
}

static uc_value_t *
rpc_ucode_blob_to_ucv(uc_vm_t *vm, struct blob_attr *attr, bool table, const char **name);

static uc_value_t *
rpc_ucode_blob_array_to_ucv(uc_vm_t *vm, struct blob_attr *attr, size_t len, bool table)
{
	uc_value_t *o = table ? ucv_object_new(vm) : ucv_array_new(vm);
	uc_value_t *v;
	struct blob_attr *pos;
	size_t rem = len;
	const char *name;

	if (!o)
		return NULL;

	__blob_for_each_attr(pos, attr, rem) {
		name = NULL;
		v = rpc_ucode_blob_to_ucv(vm, pos, table, &name);

		if (table && name)
			ucv_object_add(o, name, v);
		else if (!table)
			ucv_array_push(o, v);
		else
			ucv_put(v);
	}

	return o;
}

static uc_value_t *
rpc_ucode_blob_to_ucv(uc_vm_t *vm, struct blob_attr *attr, bool table, const char **name)
{
	void *data;
	int len;

	if (!blobmsg_check_attr(attr, false))
		return NULL;

	if (table && blobmsg_name(attr)[0])
		*name = blobmsg_name(attr);

	data = blobmsg_data(attr);
	len = blobmsg_data_len(attr);

	switch (blob_id(attr)) {
	case BLOBMSG_TYPE_BOOL:
		return ucv_boolean_new(*(uint8_t *)data);

	case BLOBMSG_TYPE_INT16:
		return ucv_int64_new((int16_t)be16_to_cpu(*(uint16_t *)data));

	case BLOBMSG_TYPE_INT32:
		return ucv_int64_new((int32_t)be32_to_cpu(*(uint32_t *)data));

	case BLOBMSG_TYPE_INT64:
		return ucv_int64_new((int64_t)be64_to_cpu(*(uint64_t *)data));

	case BLOBMSG_TYPE_DOUBLE:
		;
		union {
			double d;
			uint64_t u64;
		} v;

		v.u64 = be64_to_cpu(*(uint64_t *)data);

		return ucv_double_new(v.d);

	case BLOBMSG_TYPE_STRING:
		return ucv_string_new(data);

	case BLOBMSG_TYPE_ARRAY:
		return rpc_ucode_blob_array_to_ucv(vm, data, len, false);

	case BLOBMSG_TYPE_TABLE:
		return rpc_ucode_blob_array_to_ucv(vm, data, len, true);

	default:
		return NULL;
	}
}

static int
rpc_ucode_validate_call_args(struct ubus_object *obj, const char *ubus_method_name, struct blob_attr *msg, uc_value_t **res)
{
	rpc_ucode_script_t *script = rpc_ucode_obj_to_script(obj);
	const struct ubus_method *method = NULL;
	const struct blobmsg_hdr *hdr;
	struct blob_attr *attr;
	bool found;
	size_t i;
	int len;

	for (i = 0; i < obj->n_methods; i++) {
		if (!strcmp(obj->methods[i].name, ubus_method_name)) {
			method = &obj->methods[i];
			break;
		}
	}

	if (!method)
		return UBUS_STATUS_METHOD_NOT_FOUND;

	len = blob_len(msg);

	__blob_for_each_attr(attr, blob_data(msg), len) {
		if (!blobmsg_check_attr_len(attr, false, len))
			return UBUS_STATUS_INVALID_ARGUMENT;

		if (!blob_is_extended(attr))
			return UBUS_STATUS_INVALID_ARGUMENT;

		hdr = blob_data(attr);
		found = false;

		for (i = 0; i < method->n_policy; i++) {
			if (blobmsg_namelen(hdr) != strlen(method->policy[i].name))
				continue;

			if (strcmp(method->policy[i].name, (char *)hdr->name))
				continue;

			/* named argument found but wrong type */
			if (blob_id(attr) != method->policy[i].type)
				goto inval;

			found = true;
			break;
		}

		/* named argument not found in policy */
		if (!found) {
			/* allow special ubus_rpc_session argument */
			if (!strcmp("ubus_rpc_session", (char *)hdr->name) && blob_id(attr) == BLOBMSG_TYPE_STRING)
			    continue;

			goto inval;
		}
	}

	*res = rpc_ucode_blob_array_to_ucv(&script->vm, blob_data(msg), blob_len(msg), true);

	return UBUS_STATUS_OK;

inval:
	*res = NULL;

	return UBUS_STATUS_INVALID_ARGUMENT;
}

static uc_value_t *
rpc_ucode_gather_call_info(uc_vm_t *vm,
                           struct ubus_context *ctx, struct ubus_request_data *req,
                           struct ubus_object *obj, const char *ubus_method_name)
{
	uc_value_t *info, *o;

	info = ucv_object_new(vm);

	o = ucv_object_new(vm);

	ucv_object_add(o, "user", ucv_string_new(req->acl.user));
	ucv_object_add(o, "group", ucv_string_new(req->acl.group));
	ucv_object_add(o, "object", ucv_string_new(req->acl.object));

	ucv_object_add(info, "acl", o);

	o = ucv_object_new(vm);

	ucv_object_add(o, "id", ucv_uint64_new(obj->id));
	ucv_object_add(o, "name", ucv_string_new(obj->name));

	if (obj->path)
		ucv_object_add(o, "path", ucv_string_new(obj->path));

	ucv_object_add(info, "object", o);

	ucv_object_add(info, "method", ucv_string_new(ubus_method_name));

	return info;
}

static void
rpc_ucode_request_finish(rpc_ucode_call_ctx_t *callctx, int code, uc_value_t *reply)
{
	rpc_ucode_script_t *script = callctx->script;
	uc_resource_t *r;
	size_t i;

	if (callctx->replied)
		return;

	if (reply) {
		blob_buf_init(&buf, 0);
		rpc_ucode_ucv_object_to_blob(reply, &buf);
		ubus_send_reply(callctx->ubus, &callctx->req, buf.head);
	}

	ubus_complete_deferred_request(callctx->ubus, &callctx->req, code);

	callctx->replied = true;

	for (i = 0; i < ucv_array_length(script->pending_replies); i++) {
		r = (uc_resource_t *)ucv_array_get(script->pending_replies, i);

		if (r && r->data == callctx) {
			ucv_array_set(script->pending_replies, i, NULL);
			break;
		}
	}
}

static void
rpc_ucode_request_timeout(struct uloop_timeout *timeout)
{
	rpc_ucode_call_ctx_t *callctx = container_of(timeout, rpc_ucode_call_ctx_t, timeout);

	rpc_ucode_request_finish(callctx, UBUS_STATUS_TIMEOUT, NULL);
}

static int
rpc_ucode_script_call(struct ubus_context *ctx, struct ubus_object *obj,
                      struct ubus_request_data *req, const char *ubus_method_name,
                      struct blob_attr *msg)
{
	rpc_ucode_script_t *script = rpc_ucode_obj_to_script(obj);
	uc_value_t *func, *args = NULL, *reqobj, *reqproto, *res;
	rpc_ucode_call_ctx_t *callctx;
	const char *extype;
	size_t i;
	int rv;

	rv = rpc_ucode_validate_call_args(obj, ubus_method_name, msg, &args);

	if (rv != UBUS_STATUS_OK)
		return rv;

	func = ucv_object_get(
		ucv_object_get(rpc_ucode_obj_to_signature(obj), ubus_method_name, NULL),
		"call", NULL
	);

	if (!ucv_is_callable(func))
		return UBUS_STATUS_METHOD_NOT_FOUND;

	/* allocate deferred method call context */
	callctx = calloc(1, sizeof(*callctx));

	if (!callctx)
		return UBUS_STATUS_UNKNOWN_ERROR;

	callctx->ubus = ctx;
	callctx->script = script;

	ubus_defer_request(ctx, req, &callctx->req);

	/* create ucode request type object and set properties */
	reqobj = uc_resource_new(script->requesttype, callctx);
	reqproto = ucv_object_new(&script->vm);

	ucv_object_add(reqproto, "args", args);
	ucv_object_add(reqproto, "info",
		rpc_ucode_gather_call_info(&script->vm, ctx, req, obj, ubus_method_name));

	ucv_prototype_set(ucv_prototype_get(reqobj), reqproto);

	/* push handler and request object onto stack */
	uc_vm_stack_push(&script->vm, ucv_get(func));
	uc_vm_stack_push(&script->vm, ucv_get(reqobj));

	/* execute request handler function */
	switch (uc_vm_call(&script->vm, false, 1)) {
	case EXCEPTION_NONE:
		res = uc_vm_stack_pop(&script->vm);

		/* The handler function invoked a nested aync ubus request and returned it */
		if (ucv_resource_dataptr(res, "ubus.deferred")) {
			/* Install guard timer in case the reply callback is never called */
			callctx->timeout.cb = rpc_ucode_request_timeout;
			uloop_timeout_set(&callctx->timeout, request_timeout);

			/* Add wrapped request context into registry to prevent GC'ing
			 * until reply or timeout occurred */
			for (i = 0;; i++) {
				if (ucv_array_get(script->pending_replies, i) == NULL) {
					ucv_array_set(script->pending_replies, i, ucv_get(reqobj));
					break;
				}
			}
		}

		/* Otherwise, when the function returned an object, treat it as
		 * reply data and conclude deferred request immediately */
		else if (ucv_type(res) == UC_OBJECT) {
			blob_buf_init(&buf, 0);
			rpc_ucode_ucv_object_to_blob(res, &buf);
			ubus_send_reply(ctx, &callctx->req, buf.head);

			ubus_complete_deferred_request(ctx, &callctx->req, UBUS_STATUS_OK);
			callctx->replied = true;
		}

		/* If neither a deferred ubus request, nor a plain object were
		 * returned and if reqobj.reply() hasn't been called, immediately
		 * finish deferred request with UBUS_STATUS_NO_DATA. The */
		else if (!callctx->replied) {
			ubus_complete_deferred_request(ctx, &callctx->req, UBUS_STATUS_NO_DATA);
			callctx->replied = true;
		}

		ucv_put(res);
		break;

	/* if the handler function invoked exit(), forward exit status as ubus
	 * return code, map out of range values to UBUS_STATUS_UNKNOWN_ERROR. */
	case EXCEPTION_EXIT:
		rv = script->vm.arg.s32;

		if (rv < UBUS_STATUS_OK || rv >= __UBUS_STATUS_LAST)
			rv = UBUS_STATUS_UNKNOWN_ERROR;

		ubus_complete_deferred_request(ctx, &callctx->req, rv);
		callctx->replied = true;
		break;

	/* treat other exceptions as unknown error */
	default:
		switch (script->vm.exception.type) {
		case EXCEPTION_SYNTAX:    extype = "Syntax error";    break;
		case EXCEPTION_RUNTIME:   extype = "Runtime error";   break;
		case EXCEPTION_TYPE:      extype = "Type error";      break;
		case EXCEPTION_REFERENCE: extype = "Reference error"; break;
		default:                  extype = "Exception";
		}

		res = ucv_object_get(
			ucv_array_get(script->vm.exception.stacktrace, 0),
			"context", NULL);

		fprintf(stderr,
			"Unhandled ucode exception in '%s' method!\n%s: %s\n\n%s\n",
			ubus_method_name, extype, script->vm.exception.message,
			ucv_string_get(res));

		ubus_complete_deferred_request(ctx, &callctx->req, UBUS_STATUS_UNKNOWN_ERROR);
		callctx->replied = true;
		break;
	}

	/* release request object */
	ucv_put(reqobj);

	/* garbage collect */
	ucv_gc(&script->vm);

	return UBUS_STATUS_OK;
}

static uc_program_t *
rpc_ucode_script_compile(const char *path, uc_source_t *src)
{
	char *syntax_error = NULL;
	uc_program_t *prog;

	prog = uc_compile(&config, src, &syntax_error);

	if (!prog)
		fprintf(stderr, "Unable to compile ucode script %s: %s\n",
		        path, syntax_error);

	uc_source_put(src);
	free(syntax_error);

	return prog;
}

static bool
rpc_ucode_script_validate(rpc_ucode_script_t *script)
{
	uc_value_t *signature = uc_vm_registry_get(&script->vm, "rpcd.ucode.signature");
	uc_value_t *args, *func;

	if (ucv_type(signature) != UC_OBJECT) {
		fprintf(stderr, "Invalid object signature for ucode script %s"
		                " - expected dictionary, got %s\n",
		        script->path, ucv_typename(signature));

		return false;
	}

	ucv_object_foreach(signature, ubus_object_name, ubus_object_methods) {
		if (ucv_type(ubus_object_methods) != UC_OBJECT) {
			fprintf(stderr, "Invalid method signature for ucode script %s, object %s"
			                " - expected dictionary, got %s\n",
			        script->path, ubus_object_name, ucv_typename(ubus_object_methods));

			return false;
		}

		ucv_object_foreach(ubus_object_methods, ubus_method_name, ubus_method_definition) {
			func = ucv_object_get(ubus_method_definition, "call", NULL);
			args = ucv_object_get(ubus_method_definition, "args", NULL);

			if (ucv_type(ubus_method_definition) != UC_OBJECT) {
				fprintf(stderr, "Invalid method definition for ucode script %s, object %s, method %s"
				                " - expected dictionary, got %s\n",
				        script->path, ubus_object_name, ubus_method_name, ucv_typename(ubus_method_definition));

				return false;
			}

			if (!ucv_is_callable(func)) {
				fprintf(stderr, "Invalid method callback for ucode script %s, object %s, method %s"
				                " - expected callable, got %s\n",
				        script->path, ubus_object_name, ubus_method_name, ucv_typename(func));

				return false;
			}

			if (args) {
				if (ucv_type(args) != UC_OBJECT) {
					fprintf(stderr, "Invalid method argument definition for ucode script %s, "
					                "object %s, method %s  - expected dictionary, got %s\n",
					        script->path, ubus_object_name, ubus_method_name, ucv_typename(args));

					return false;
				}

				ucv_object_foreach(args, ubus_argument_name, ubus_argument_typehint) {
					switch (ucv_type(ubus_argument_typehint)) {
					case UC_BOOLEAN:
					case UC_INTEGER:
					case UC_DOUBLE:
					case UC_STRING:
					case UC_ARRAY:
					case UC_OBJECT:
						continue;

					default:
						fprintf(stderr, "Unsupported argument type for ucode script %s, object %s, "
						                "method %s, argument %s  - expected boolean, integer, string, "
						                "array or object, got %s\n",
						        script->path, ubus_object_name, ubus_method_name, ubus_argument_name,
						        ucv_typename(ubus_argument_typehint));

						return false;
					}
				}
			}
		}
	}

	return true;
}

static bool
rpc_ucode_method_register(struct ubus_method *method, const char *ubus_method_name, uc_value_t *ubus_method_arguments)
{
	struct blobmsg_policy *policy;
	enum blobmsg_type type;

	method->name = strdup(ubus_method_name);

	if (!method->name) {
		fprintf(stderr, "Unable to allocate ubus method name: %s\n",
		        strerror(errno));

		return false;
	}

	method->policy = calloc(ucv_object_length(ubus_method_arguments), sizeof(*method->policy));

	if (!method->policy) {
		fprintf(stderr, "Unable to allocate ubus method argument policy: %s\n",
		        strerror(errno));

		return false;
	}

	method->handler = rpc_ucode_script_call;

	ucv_object_foreach(ubus_method_arguments, ubus_argument_name, ubus_argument_typehint) {
		switch (ucv_type(ubus_argument_typehint)) {
		case UC_BOOLEAN:
			type = BLOBMSG_TYPE_INT8;
			break;

		case UC_INTEGER:
			switch (ucv_int64_get(ubus_argument_typehint)) {
			case 8:
				type = BLOBMSG_TYPE_INT8;
				break;

			case 16:
				type = BLOBMSG_TYPE_INT16;
				break;

			case 64:
				type = BLOBMSG_TYPE_INT64;
				break;

			default:
				type = BLOBMSG_TYPE_INT32;
				break;
			}

			break;

		case UC_DOUBLE:
			type = BLOBMSG_TYPE_DOUBLE;
			break;

		case UC_ARRAY:
			type = BLOBMSG_TYPE_ARRAY;
			break;

		case UC_OBJECT:
			type = BLOBMSG_TYPE_TABLE;
			break;

		default:
			type = BLOBMSG_TYPE_STRING;
			break;
		}

		policy = (struct blobmsg_policy *)&method->policy[method->n_policy++];

		policy->type = type;
		policy->name = strdup(ubus_argument_name);

		if (!policy->name) {
			fprintf(stderr, "Unable to allocate ubus method argument name: %s\n",
			        strerror(errno));

			return false;
		}
	}

	return true;
}

static bool
rpc_ucode_script_register(struct ubus_context *ctx, rpc_ucode_script_t *script)
{
	uc_value_t *signature = uc_vm_registry_get(&script->vm, "rpcd.ucode.signature");
	const struct blobmsg_policy *policy;
	rpc_ucode_ubus_obj_t *uuobj = NULL;
	char *tptr, *tnptr, *onptr, *mptr;
	struct ubus_method *method;
	struct ubus_object *obj;
	size_t typelen, namelen;
	uc_value_t *args;
	int rv;

	if (!rpc_ucode_script_validate(script))
		return false;

	ucv_object_foreach(signature, ubus_object_name, ubus_object_methods) {
		namelen = strlen(ubus_object_name);
		typelen = strlen("rpcd-plugin-ucode-") + namelen;

		uuobj = calloc_a(sizeof(*uuobj),
		                 &onptr, namelen + 1,
		                 &mptr, ucv_object_length(ubus_object_methods) * sizeof(struct ubus_method),
		                 &tptr, sizeof(struct ubus_object_type),
		                 &tnptr, typelen + 1);

		if (!uuobj) {
			fprintf(stderr, "Unable to allocate ubus object signature: %s\n",
			        strerror(errno));

			continue;
		}

		list_add(&uuobj->list, &uuobjs);

		uuobj->script = script;
		uuobj->signature = ubus_object_methods;

		snprintf(tnptr, typelen, "rpcd-plugin-ucode-%s", ubus_object_name);

		method = (struct ubus_method *)mptr;

		obj = &uuobj->ubusobj;
		obj->name = strncpy(onptr, ubus_object_name, namelen);
		obj->methods = method;

		obj->type = (struct ubus_object_type *)tptr;
		obj->type->name = tnptr;
		obj->type->methods = obj->methods;

		ucv_object_foreach(ubus_object_methods, ubus_method_name, ubus_method_definition) {
			args = ucv_object_get(ubus_method_definition, "args", NULL);

			if (!rpc_ucode_method_register(&method[obj->n_methods++], ubus_method_name, args))
				goto free;
		}

		obj->type = (struct ubus_object_type *)tptr;
		obj->type->name = tnptr;
		obj->type->methods = obj->methods;
		obj->type->n_methods = obj->n_methods;

		rv = ubus_add_object(ctx, obj);

		if (rv != UBUS_STATUS_OK) {
			fprintf(stderr, "Unable to register ubus object %s: %s\n",
			        obj->name, ubus_strerror(rv));

			goto free;
		}

		continue;

free:
		for (; obj->n_methods > 0; method++, obj->n_methods--) {
			for (policy = method->policy; method->n_policy > 0; policy++, method->n_policy--)
				free((char *)policy->name);

			free((char *)method->name);
			free((char *)method->policy);
		}

		free(uuobj);
	}

	return true;
}

static uc_value_t *
rpc_ucode_request_reply(uc_vm_t *vm, size_t nargs)
{
	rpc_ucode_call_ctx_t **callctx = uc_fn_this("rpcd.ucode.request");
	uc_value_t *reply = uc_fn_arg(0);
	uc_value_t *rcode = uc_fn_arg(1);
	int64_t code = UBUS_STATUS_OK;

	if (!callctx || !*callctx) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Attempt to invoke reply() on invalid self");

		return NULL;
	}
	else if (reply && ucv_type(reply) != UC_OBJECT) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "First argument to reply() must be null or an object");

		return NULL;
	}
	else if (rcode && ucv_type(rcode) != UC_INTEGER) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Second argument to reply() must be null or an integer");

		return NULL;
	}

	if ((*callctx)->replied) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Reply has already been sent");

		return NULL;
	}

	if (rcode) {
		code = ucv_int64_get(rcode);

		if (errno == ERANGE || code < 0 || code > __UBUS_STATUS_LAST)
			code = UBUS_STATUS_UNKNOWN_ERROR;
	}

	rpc_ucode_request_finish(*callctx, code, reply);

	return NULL;
}

static uc_value_t *
rpc_ucode_request_error(uc_vm_t *vm, size_t nargs)
{
	rpc_ucode_call_ctx_t **callctx = uc_fn_this("rpcd.ucode.request");
	uc_value_t *rcode = uc_fn_arg(0);
	int64_t code;

	if (!callctx || !*callctx) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Attempt to invoke error() on invalid self");

		return NULL;
	}
	else if (ucv_type(rcode) != UC_INTEGER) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "First argument to error() must be an integer");

		return NULL;
	}

	if ((*callctx)->replied) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Reply has already been sent");

		return NULL;
	}


	code = ucv_int64_get(rcode);

	if (errno == ERANGE || code < 0 || code > __UBUS_STATUS_LAST)
		code = UBUS_STATUS_UNKNOWN_ERROR;

	rpc_ucode_request_finish(*callctx, code, NULL);

	return NULL;
}

static const uc_function_list_t rpc_ucode_request_fns[] = {
	{ "reply", rpc_ucode_request_reply },
	{ "error", rpc_ucode_request_error },
};

static void
rpc_ucode_request_gc(void *ud)
{
	rpc_ucode_call_ctx_t *callctx = ud;

	uloop_timeout_cancel(&callctx->timeout);
	free(callctx);
}

static void
rpc_ucode_init_globals(rpc_ucode_script_t *script)
{
	uc_vm_t *vm = &script->vm;
	uc_value_t *scope = uc_vm_scope_get(vm);

#define status_const(name) \
	ucv_object_add(scope, #name, ucv_uint64_new(name))

	status_const(UBUS_STATUS_OK);
	status_const(UBUS_STATUS_INVALID_COMMAND);
	status_const(UBUS_STATUS_INVALID_ARGUMENT);
	status_const(UBUS_STATUS_METHOD_NOT_FOUND);
	status_const(UBUS_STATUS_NOT_FOUND);
	status_const(UBUS_STATUS_NO_DATA);
	status_const(UBUS_STATUS_PERMISSION_DENIED);
	status_const(UBUS_STATUS_TIMEOUT);
	status_const(UBUS_STATUS_NOT_SUPPORTED);
	status_const(UBUS_STATUS_UNKNOWN_ERROR);
	status_const(UBUS_STATUS_CONNECTION_FAILED);

#undef status_const

	uc_stdlib_load(scope);

	script->requesttype = uc_type_declare(vm, "rpcd.ucode.request",
		rpc_ucode_request_fns, rpc_ucode_request_gc);
}

static rpc_ucode_script_t *
rpc_ucode_script_execute(struct ubus_context *ctx, const char *path, uc_program_t *prog)
{
	rpc_ucode_script_t *script;
	uc_value_t *signature;
	uc_vm_status_t status;
	size_t pathlen;
	char *pptr;

	pathlen = strlen(path);
	script = calloc_a(sizeof(*script), &pptr, pathlen + 1);

	if (!script) {
		fprintf(stderr, "Unable to allocate context for ucode script %s: %s\n",
		        path, strerror(errno));

		uc_program_put(prog);

		return NULL;
	}

	script->path = strncpy(pptr, path, pathlen);

	uc_vm_init(&script->vm, &config);
	rpc_ucode_init_globals(script);

	status = uc_vm_execute(&script->vm, prog, &signature);

	script->pending_replies = ucv_array_new(&script->vm);

	uc_vm_registry_set(&script->vm, "rpcd.ucode.signature", signature);
	uc_vm_registry_set(&script->vm, "rpcd.ucode.deferreds", script->pending_replies);

	uc_program_put(prog);
	ucv_gc(&script->vm);

	switch (status) {
	case STATUS_OK:
		if (rpc_ucode_script_register(ctx, script))
			return script;

		fprintf(stderr, "Skipping registration of ucode script %s\n", path);
		break;

	case STATUS_EXIT:
		fprintf(stderr, "The ucode script %s invoked exit(%" PRId64 ")\n",
		        path, ucv_int64_get(signature));
		break;

	case ERROR_COMPILE:
		fprintf(stderr, "Compilation error while executing ucode script %s\n", path);
		break;

	case ERROR_RUNTIME:
		fprintf(stderr, "Runtime error while executing ucode script %s\n", path);
		break;
	}

	uc_vm_free(&script->vm);
	free(script);

	return NULL;
}

static int
rpc_ucode_init_script(struct ubus_context *ctx, const char *path)
{
	rpc_ucode_script_t *script;
	uc_program_t *prog;
	uc_source_t *src;

	src = uc_source_new_file(path);

	if (!src) {
		fprintf(stderr, "Unable to open ucode script %s: %s\n",
		        path, strerror(errno));

		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	prog = rpc_ucode_script_compile(path, src);

	if (!prog)
		return UBUS_STATUS_UNKNOWN_ERROR;

	script = rpc_ucode_script_execute(ctx, path, prog);

	if (!script)
		return UBUS_STATUS_UNKNOWN_ERROR;

	list_add(&script->list, &scripts);

	return UBUS_STATUS_OK;
}

static int
rpc_ucode_api_init(const struct rpc_daemon_ops *ops, struct ubus_context *ctx)
{
	char path[PATH_MAX];
	struct dirent *e;
	struct stat s;
	int rv = 0;
	DIR *d;

	request_timeout = *ops->exec_timeout;

	/* reopen ucode.so with RTLD_GLOBAL in order to export libucode runtime
	 * symbols for ucode extensions loaded later at runtime */
	if (!dlopen(RPC_LIBRARY_DIRECTORY "/ucode.so", RTLD_LAZY|RTLD_GLOBAL)) {
		fprintf(stderr, "Failed to dlopen() ucode.so: %s, dynamic ucode plugins may fail\n",
		        dlerror());
	}

	/* initialize default module search path */
	uc_search_path_init(&config.module_search_path);

	if ((d = opendir(RPC_UCSCRIPT_DIRECTORY)) != NULL) {
		while ((e = readdir(d)) != NULL) {
			snprintf(path, sizeof(path), RPC_UCSCRIPT_DIRECTORY "/%s", e->d_name);

			if (stat(path, &s) || !S_ISREG(s.st_mode))
				continue;

			if (s.st_mode & S_IWOTH) {
				fprintf(stderr, "Ignoring ucode script %s because it is world writable\n",
				        path);

				continue;
			}

			rv |= rpc_ucode_init_script(ctx, path);
		}

		closedir(d);
	}

	return rv;
}

struct rpc_plugin rpc_plugin = {
	.init = rpc_ucode_api_init
};
