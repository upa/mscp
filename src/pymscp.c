#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <mscp.h>

/*
 * This is a wrapper for python binding of libmscp.  setup.py builds
 * pymscp.c after libmscp was built, and setup.py installs pymscp
 * modlue and mscp python module (mscp/mscp.py), which is a warpper
 * for pymscp.
 */

#define MAX_MSCP_INSTS	16

/* XXX: cut corners */
struct mscp *insts[MAX_MSCP_INSTS];

static int add_mscp_inst(struct mscp *m)
{
	int n;
	for (n = 0; n < MAX_MSCP_INSTS; n++) {
		if (insts[n] == NULL) {
			insts[n] = m;
			return 0;
		}
	}

	return -1; /* full of mscp instances */
}

static struct mscp *get_mscp_inst(unsigned long long maddr)
{
	int n;
	for (n = 0; n < MAX_MSCP_INSTS; n++) {
		if (insts[n] == (void *)maddr)
			return insts[n];
	}

	return NULL;
}

static int release_mscp_inst(struct mscp *m)
{
	int n;
	for (n = 0; n < MAX_MSCP_INSTS; n++) {
		if (insts[n] == m) {
			insts[n] = NULL;
			return 0;
		}
	}
	return -1;
}


/* wrapper functions */

static PyObject *wrap_mscp_init(PyObject *sef, PyObject *args, PyObject *kw)
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
		"severity",	/* int, MSCP_SERVERITY_* */
		"msg_fd",	/* int */

		/*  mscp_ssh_opts */
		"login_name",	/* const char * */
		"port",		/* const char * */
		"identity",	/* const char * */
		"cipher",	/* const char * */
		"hmac",		/* const char * */
		"compress",	/* const char * */
		"password",	/* const char * */
		"passphrase",	/* const char * */
		"debug_level",	/* int */
		"no_hostkey_check",	/* bool */
		"enable_nagle",		/* bool */
		NULL,
	};
	const char *fmt = "si" "|iikkkzii" "zzzzzzzzipp";
	char *coremask = NULL;
	char *login_name = NULL, *port = NULL, *identity = NULL;
	char *cipher = NULL, *hmac = NULL, *compress = NULL;
	char *password = NULL, *passphrase = NULL;

	struct mscp_ssh_opts so;
	struct mscp_opts mo;
	struct mscp *m;
	int direction;
	int ret;

	memset(&mo, 0, sizeof(mo));
	memset(&so, 0, sizeof(so));
	
	ret = PyArg_ParseTupleAndKeywords(args, kw, fmt, keywords,
					  &remote,
					  &direction,
					  &mo.nr_threads,
					  &mo.nr_ahead,
					  &mo.min_chunk_sz,
					  &mo.max_chunk_sz,
					  &mo.buf_sz,
					  &coremask,
					  &mo.severity,
					  &mo.msg_fd,
					  &login_name,
					  &port,
					  &identity,
					  &cipher,
					  &hmac,
					  &compress,
					  &password,
					  &passphrase,
					  &so.debug_level,
					  &so.no_hostkey_check,
					  &so.enable_nagle);
		
	if (!ret)
		return NULL;

	if (coremask)
		strncpy(mo.coremask, coremask, MSCP_MAX_COREMASK_STR - 1);
	if (login_name)
		strncpy(so.login_name, login_name, MSCP_SSH_MAX_LOGIN_NAME - 1);
	if (port)
		strncpy(so.port, port, MSCP_SSH_MAX_PORT_STR - 1);
	if (identity)
		strncpy(so.identity, identity, MSCP_SSH_MAX_IDENTITY_PATH - 1);
	if (cipher)
		strncpy(so.cipher, cipher, MSCP_SSH_MAX_CIPHER_STR - 1);
	if (hmac)
		strncpy(so.hmac, hmac, MSCP_SSH_MAX_HMAC_STR - 1);
	if (compress)
		strncpy(so.compress, compress, MSCP_SSH_MAX_COMP_STR - 1);
	if (password)
		strncpy(so.password, password, MSCP_SSH_MAX_PASSWORD - 1);
	if (passphrase)
		strncpy(so.passphrase, passphrase, MSCP_SSH_MAX_PASSPHRASE - 1);

	
	m = mscp_init(remote, direction, &mo, &so);
	if (!m)
		return NULL;

	if (add_mscp_inst(m) < 0) {
		PyErr_Format(PyExc_RuntimeError, "too many mscp isntances");
		mscp_free(m);
		return NULL;
	}

	return Py_BuildValue("K", (unsigned long long)m);
}

static PyObject *wrap_mscp_connect(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
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
	unsigned long long maddr;
	char *src_path;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "Ks", keywords, &maddr, &src_path))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
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
	unsigned long long maddr;
	char *dst_path;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "Ks", keywords, &maddr, &dst_path))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
		return NULL;
	}

	if (mscp_set_dst_path(m, dst_path) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_prepare(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
		return NULL;
	}

	if (mscp_prepare(m) < 0) {
		PyErr_Format(PyExc_RuntimeError, mscp_get_error());
		return NULL;
	}

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_start(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
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
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
		return NULL;
	}

	mscp_stop(m);

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_join(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
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
	unsigned long long maddr;
	struct mscp_stats s;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
		return NULL;
	}

	mscp_get_stats(m, &s);

	return Py_BuildValue("KKd", s.total, s.done, s.finished);
}

static PyObject *wrap_mscp_cleanup(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
		return NULL;
	}

	mscp_cleanup(m);

	return Py_BuildValue("");
}

static PyObject *wrap_mscp_free(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = get_mscp_inst(maddr);
	if (!m) {
		PyErr_Format(PyExc_RuntimeError, "invalid mscp address");
		return NULL;
	}

	release_mscp_inst(m);
	mscp_free(m);

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
		"mscp_prepare", (PyCFunction)wrap_mscp_prepare,
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

