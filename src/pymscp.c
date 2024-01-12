/* SPDX-License-Identifier: GPL-3.0-only */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <mscp.h>

/*
 * This is a wrapper for python binding of libmscp. setup.py builds
 * pymscp.c after libmscp was built, and setup.py installs pymscp
 * modlue and mscp python module (mscp/mscp.py), which is a warpper
 * for pymscp.
 */

#define MAX_MSCP_INSTS	64

/* XXX: cut corners */
struct instance {
	struct mscp_opts mo;
	struct mscp_ssh_opts so;
	struct mscp *m;
};

struct instance *insts[MAX_MSCP_INSTS];

static int add_instance(struct instance *i)
{
	int n;
	for (n = 0; n < MAX_MSCP_INSTS; n++) {
		if (insts[n] == NULL) {
			insts[n] = i;
			return 0;
		}
	}

	return -1; /* full of mscp instances */
}

static struct instance *get_instance(unsigned long long addr)
{
	int n;
	for (n = 0; n < MAX_MSCP_INSTS; n++) {
		if (insts[n] == (void *)addr)
			return insts[n];
	}

	return NULL;
}

static struct mscp *get_mscp(unsigned long long addr)
{
	struct instance *i = get_instance(addr);

	if (!i)
		return NULL;
	return i->m;
}

static int release_instance(struct instance *i)
{
	int n;
	for (n = 0; n < MAX_MSCP_INSTS; n++) {
		if (insts[n] == i) {
			insts[n] = NULL;
			return 0;
		}
	}

	free(i);

	return -1;
}


/* wrapper functions */

static PyObject *wrap_mscp_init(PyObject *self, PyObject *args, PyObject *kw)
{
	/*
	 * Initialize struct mscp with options.  wrap_mscp_init
	 * receives all the arguments with keywords.
	 */

	char *remote;
	char *keywords[] = {
		"remote",	/* const char * */
		"direction",	/* int, MSCP_DIRECTION_L2R or MSCP_DIRECTION_R2L */

		/* mscp_opts */
		"nr_threads", 	/* int */
		"nr_ahead",	/* int */

		"min_chunk_sz",	/* unsigned long */
		"max_chunk_sz",	/* unsigned long */
		"buf_sz",	/* unsigned long */

		"coremask",	/* const char * */

		"max_startups",	/* int */
		"interval",	/* int */
		"severity",	/* int, MSCP_SERVERITY_* */
		"msg_fd",	/* int */

		/*  mscp_ssh_opts */
		"login_name",	/* const char * */
		"port",		/* const char * */
		"config",	/* const char * */
		"identity",	/* const char * */

		"cipher",	/* const char * */
		"hmac",		/* const char * */
		"compress",	/* const char * */
		"ccalgo",       /* const char * */
		"password",	/* const char * */
		"passphrase",	/* const char * */

		"debug_level",	/* int */
		"no_hostkey_check",	/* bool */
		"enable_nagle",		/* bool */
		NULL,
	};
	const char *fmt = "si" "|" "ii" "kkk" "s" "iiii" "ssss" "ssssss" "ipp";
	char *coremask = NULL;
	char *login_name = NULL, *port = NULL, *config = NULL, *identity = NULL;
	char *cipher = NULL, *hmac = NULL, *compress = NULL, *ccalgo = NULL;
	char *password = NULL, *passphrase = NULL;

	struct instance *i;
	int direction;
	int ret;

	i = malloc(sizeof(*i));
	if (!i) {
		PyErr_Format(PyExc_RuntimeError, strerror(errno));
		return NULL;
	}

	memset(i, 0, sizeof(*i));
	
	ret = PyArg_ParseTupleAndKeywords(args, kw, fmt, keywords,
					  &remote,
					  &direction,
					  &i->mo.nr_threads,
					  &i->mo.nr_ahead,
					  &i->mo.min_chunk_sz,
					  &i->mo.max_chunk_sz,
					  &i->mo.buf_sz,
					  &coremask,
					  &i->mo.max_startups,
					  &i->mo.interval,
					  &i->mo.severity,
					  &i->mo.msg_fd,
					  &login_name,
					  &port,
					  &config,
					  &identity,
					  &cipher,
					  &hmac,
					  &compress,
					  &ccalgo,
					  &password,
					  &passphrase,
					  &i->so.debug_level,
					  &i->so.no_hostkey_check,
					  &i->so.enable_nagle);
		
	if (!ret)
		return NULL;

	if (coremask)
		strncpy(i->mo.coremask, coremask, MSCP_MAX_COREMASK_STR - 1);
	if (login_name)
		strncpy(i->so.login_name, login_name, MSCP_SSH_MAX_LOGIN_NAME - 1);
	if (port)
		strncpy(i->so.port, port, MSCP_SSH_MAX_PORT_STR - 1);
	if (config)
		strncpy(i->so.config, config, PATH_MAX - 1);
	if (identity)
		strncpy(i->so.identity, identity, MSCP_SSH_MAX_IDENTITY_PATH - 1);
	if (cipher)
		strncpy(i->so.cipher, cipher, MSCP_SSH_MAX_CIPHER_STR - 1);
	if (hmac)
		strncpy(i->so.hmac, hmac, MSCP_SSH_MAX_HMAC_STR - 1);
	if (compress)
		strncpy(i->so.compress, compress, MSCP_SSH_MAX_COMP_STR - 1);
	if (ccalgo)
		strncpy(i->so.ccalgo, ccalgo, MSCP_SSH_MAX_CCALGO_STR - 1);
	if (password)
		strncpy(i->so.password, password, MSCP_SSH_MAX_PASSWORD - 1);
	if (passphrase)
		strncpy(i->so.passphrase, passphrase, MSCP_SSH_MAX_PASSPHRASE - 1);

	i->m = mscp_init(remote, direction, &i->mo, &i->so);
	if (!i->m) {
		PyErr_Format(PyExc_RuntimeError, "%s", mscp_get_error());
		free(i);
		return NULL;
	}

	if (add_instance(i) < 0) {
		PyErr_Format(PyExc_RuntimeError, "too many mscp isntances");
		mscp_free(i->m);
		free(i);
		return NULL;
	}

	return Py_BuildValue("K", (unsigned long long)i);
}

static PyObject *wrap_mscp_connect(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	if (mscp_connect(m) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_add_src_path(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", "src_path", NULL };
	unsigned long long addr;
	char *src_path;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "Ks", keywords, &addr, &src_path))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	if (mscp_add_src_path(m, src_path) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_set_dst_path(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", "dst_path", NULL };
	unsigned long long addr;
	char *dst_path;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "Ks", keywords, &addr, &dst_path))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	if (mscp_set_dst_path(m, dst_path) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_scan(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	if (mscp_scan(m) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_start(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	if (mscp_start(m) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_stop(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	mscp_stop(m);

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_join(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	if (mscp_join(m) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_get_stats(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp_stats s;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	mscp_get_stats(m, &s);

	return Py_BuildValue("KKO", s.total, s.done, PyBool_FromLong(s.finished));
}

static PyObject *wrap_mscp_cleanup(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	m = get_mscp(addr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	mscp_cleanup(m);

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_free(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long addr;
	struct instance *i;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &addr))
		return NULL;

	i = get_instance(addr);
	if (!i) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp instance address");
		return NULL;
	}

	mscp_free(i->m);
	release_instance(i);

	return Py_BuildValue("");
}

static PyMethodDef pymscpMethods[] = {
	{
		"mscp_init", (PyCFunction)wrap_mscp_init,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_connect", (PyCFunction)wrap_mscp_connect,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_add_src_path", (PyCFunction)wrap_mscp_add_src_path,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_set_dst_path", (PyCFunction)wrap_mscp_set_dst_path,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_scan", (PyCFunction)wrap_mscp_scan,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_start", (PyCFunction)wrap_mscp_start,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_stop", (PyCFunction)wrap_mscp_stop,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_join", (PyCFunction)wrap_mscp_join,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_get_stats", (PyCFunction)wrap_mscp_get_stats,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_cleanup", (PyCFunction)wrap_mscp_cleanup,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"mscp_free", (PyCFunction)wrap_mscp_free,
		METH_VARARGS | METH_KEYWORDS, NULL
	},
	{ NULL, NULL, 0, NULL },
};

static PyModuleDef pymscpModule = {
	PyModuleDef_HEAD_INIT, "pymscp", NULL, -1, pymscpMethods,
};

PyMODINIT_FUNC PyInit_pymscp(void) {
	PyObject *mod = PyModule_Create(&pymscpModule);

	PyModule_AddIntConstant(mod, "LOCAL2REMOTE",	MSCP_DIRECTION_L2R);
	PyModule_AddIntConstant(mod, "REMOTE2LOCAL",	MSCP_DIRECTION_R2L);
	PyModule_AddIntConstant(mod, "SEVERITY_NONE",	MSCP_SEVERITY_NONE);
	PyModule_AddIntConstant(mod, "SEVERITY_ERR",	MSCP_SEVERITY_ERR);
	PyModule_AddIntConstant(mod, "SEVERITY_WARN",	MSCP_SEVERITY_WARN);
	PyModule_AddIntConstant(mod, "SEVERITY_NOTICE",	MSCP_SEVERITY_NOTICE);
	PyModule_AddIntConstant(mod, "SEVERITY_INFO",	MSCP_SEVERITY_INFO);
	PyModule_AddIntConstant(mod, "SEVERITY_DEBUG",	MSCP_SEVERITY_DEBUG);

	return mod;
}

