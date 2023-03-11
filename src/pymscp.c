#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <mscp.h>

static PyObject *wrap_mscp_init(PyObject *sef, PyObject *args, PyObject *kw)
{
	/*
	 * Initialize struct mscp with options.  wrap_mscp_init
	 * receives all the arguments with keywords.
	 */

	char *remote;
	char *keywords[] = {
		/* mscp_opts */
		"direction",	/* int, MSCP_DIRECTION_L2R or MSCP_DIRECTION_R2L */
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
	const char *fmt = "siiikkkzii" "zzzzzzzzipp";
	char *coremask;
	char *login_name, *port, *identity, *cipher, *hmac, *compress;
	char *password, *passphrase;

	struct mscp_opts mo;
	struct mscp_ssh_opts so;
	struct mscp *m;
	int ret;

	memset(&mo, 0, sizeof(mo));
	memset(&so, 0, sizeof(so));
	
	ret = PyArg_ParseTupleAndKeywords(args, kw, fmt, keywords,
					  &remote,
					  &mo.direction,
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
					  &so.no_hostkey_check,
					  &so.enable_nagle);
		
	if (!ret)
		return NULL;

	if (coremask)
		strncpy(mo.coremask, coremask, MSCP_MAX_COREMASK_STR);
	if (login_name)
		strncpy(so.login_name, login_name, MSCP_SSH_MAX_LOGIN_NAME);
	if (port)
		strncpy(so.port, port, MSCP_SSH_MAX_PORT_STR);
	if (identity)
		strncpy(so.identity, identity, MSCP_SSH_MAX_IDENTITY_PATH);
	if (cipher)
		strncpy(so.cipher, cipher, MSCP_SSH_MAX_CIPHER_STR);
	if (hmac)
		strncpy(so.hmac, hmac, MSCP_SSH_MAX_HMAC_STR);
	if (compress)
		strncpy(so.compress, compress, MSCP_SSH_MAX_COMP_STR);
	if (password)
		strncpy(so.password, password, MSCP_SSH_MAX_PASSWORD);
	if (passphrase)
		strncpy(so.passphrase, passphrase, MSCP_SSH_MAX_PASSPHRASE);

	
	m = mscp_init(remote, &mo, &so);
	if (!m)
		return NULL;

	return Py_BuildValue("K", (unsigned long long)m);
}

static PyObject *wrap_mscp_connect(PyObject *self, PyObject *args, PyObject *kw)
{
	char *keywords[] = { "m", NULL };
	unsigned long long maddr;
	struct mscp *m;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "K", keywords, &maddr))
		return NULL;

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
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

	m = (void *)maddr;
	mscp_free(m);

	return Py_BuildValue("");
}

static PyMethodDef PyMscpMethods[] = {
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

static PyModuleDef PyMscpModule = {
	PyModuleDef_HEAD_INIT, "PyMscp", NULL, -1, PyMscpMethods,
};

PyMODINIT_FUNC PyInit_PyMscp(void) {
	return PyModule_Create(&PyMscpModule);
}

