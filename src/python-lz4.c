/*
 * Copyright (c) 2012-2013, Steeve Morin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Steeve Morin nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <Python.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "lz4.h"
#include "lz4hc.h"
#include "python-lz4.h"

#define MAX(a, b)               ((a) > (b) ? (a) : (b))

#if PY_MAJOR_VERSION >= 3
/***** Python 3 *****/
#define IS_PY3 1
#else
/***** Python 2 *****/
#define IS_PY3 0
#endif


typedef int (*compressor)(const char *source, char *dest, int isize);

static inline void store_le32(char *c, uint32_t x) {
    c[0] = x & 0xff;
    c[1] = (x >> 8) & 0xff;
    c[2] = (x >> 16) & 0xff;
    c[3] = (x >> 24) & 0xff;
}

static inline uint32_t load_le32(const char *c) {
    const uint8_t *d = (const uint8_t *)c;
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24);
}

static inline void store_be32(char *c, uint32_t x) {
    c[3] = x & 0xff;
    c[2] = (x >> 8) & 0xff;
    c[1] = (x >> 16) & 0xff;
    c[0] = (x >> 24) & 0xff;
}

static inline uint32_t load_be32(const char *c) {
    const uint8_t *d = (const uint8_t *)c;
    return d[3] | (d[2] << 8) | (d[1] << 16) | (d[0] << 24);
}


inline const char* VarintParse32WithLimit(const char* p,
                                            const char* l,
                                            uint32_t* OUTPUT) {
    const unsigned char* ptr = (const unsigned char*)(p);
    const unsigned char* limit = (const unsigned char*)(l);
    uint32_t b, result;
    if (ptr >= limit) return NULL;
    b = *(ptr++); result = b & 127;          if (b < 128) goto done;
    if (ptr >= limit) return NULL;
    b = *(ptr++); result |= (b & 127) <<  7; if (b < 128) goto done;
    if (ptr >= limit) return NULL;
    b = *(ptr++); result |= (b & 127) << 14; if (b < 128) goto done;
    if (ptr >= limit) return NULL;
    b = *(ptr++); result |= (b & 127) << 21; if (b < 128) goto done;
    if (ptr >= limit) return NULL;
    b = *(ptr++); result |= (b & 127) << 28; if (b < 16) goto done;
    return NULL;       // Value is too long to be a varint32
done:
    *OUTPUT = result;
    return (const char*)(ptr);
}

inline char* VarintEncode32(char* sptr, uint32_t v) {
    // Operate on characters as unsigneds
    unsigned char* ptr = (unsigned char*)(sptr);
    static const int B = 128;
    if (v < (1<<7)) {
        *(ptr++) = v;
    } else if (v < (1<<14)) {
        *(ptr++) = v | B;
        *(ptr++) = v>>7;
    } else if (v < (1<<21)) {
        *(ptr++) = v | B;
        *(ptr++) = (v>>7) | B;
        *(ptr++) = v>>14;
    } else if (v < (1<<28)) {
        *(ptr++) = v | B;
        *(ptr++) = (v>>7) | B;
        *(ptr++) = (v>>14) | B;
        *(ptr++) = v>>21;
    } else {
        *(ptr++) = v | B;
        *(ptr++) = (v>>7) | B;
        *(ptr++) = (v>>14) | B;
        *(ptr++) = (v>>21) | B;
        *(ptr++) = v>>28;
    }
    return (char*)(ptr);
}


//static const int hdr_size = sizeof(uint32_t);

static PyObject *compress_with(compressor compress, PyObject *self, PyObject *args, PyObject * keywds) {
    PyObject *result = NULL;
    char *dest = NULL;
    int dest_size = 0;

    Py_buffer source;
    int head_type = 1; // le32
    int return_bytearray = 0;
    int hdr_size = sizeof(uint32_t);

    static char *kwlist[] = { "data", 
                            "head_type", // 0:none 1:le32 2:be32 3:varint
                            "return_bytearray",
                            NULL
                          };

#if IS_PY3
    if (!PyArg_ParseTupleAndKeywords (args, keywds, "s*|ii", kwlist,
                                    &source,
                                    &head_type,
                                    &return_bytearray))
    {
      return NULL;
    }
#else
  if (!PyArg_ParseTupleAndKeywords (args, keywds, "s*|ii", kwlist,
                                    &source,
                                    &head_type,
                                    &return_bytearray))
    {
      return NULL;
    }
#endif
    if (source.len == 0) {
        return NULL;
    }

    switch (head_type) {
    // none
    case 0:
        hdr_size = 0;
        break;
    // varint
    case 3: {
        char buf[8] = {0};
        char* p = VarintEncode32(buf, source.len);
        hdr_size = p - buf;
        }
        break;
    // le32
    case 1:
    // be32
    case 2:
    // le32
    default:
        hdr_size = sizeof(uint32_t);
        break;
    }

    dest_size = hdr_size + LZ4_compressBound(source.len);
    result = PyBytes_FromStringAndSize(NULL, dest_size);
    if (result == NULL) {
        return NULL;
    }
    dest = PyBytes_AS_STRING(result);

    switch (head_type) {
    // none
    case 0: 
        break;
    // varint
    case 3: 
        VarintEncode32(dest, source.len);
        break;
    // le32
    case 1:
        store_le32(dest, source.len);
        break;
    // be32
    case 2:
        store_be32(dest, source.len);
        break;
    // le32
    default:
        store_le32(dest, source.len);
        break;
    }


    if (source.len > 0) {
        int osize = 0;
        Py_BEGIN_ALLOW_THREADS
        osize = compress(source.buf, dest + hdr_size, source.len);
        Py_END_ALLOW_THREADS
        int actual_size = hdr_size + osize;
        /* Resizes are expensive; tolerate some slop to avoid. */
        if (actual_size < (dest_size / 4) * 3) {
            _PyBytes_Resize(&result, actual_size);
        } else {
            Py_SIZE(result) = actual_size;
        }
    }
    return result;
}

static PyObject *py_lz4_compress(PyObject *self, PyObject *args, PyObject * keywds) {
    return compress_with(LZ4_compress, self, args, keywds);
}

static PyObject *py_lz4_compressHC(PyObject *self, PyObject *args, PyObject * keywds) {
    return compress_with(LZ4_compressHC, self, args, keywds);
}

static PyObject *py_lz4_uncompress(PyObject *self, PyObject *args, PyObject * keywds) {
    PyObject *result = NULL;
    uint32_t dest_size = 0;

    Py_buffer source;
    int head_type = 1; // le32
    int return_bytearray = 0;
    int max_size = 0;
    int hdr_size = sizeof(uint32_t);

    static char *kwlist[] = { "data", 
                            "head_type", // 0:none 1:le32 2:be32 3:varint
                            "max_size",
                            "return_bytearray",
                            NULL
                          };

#if IS_PY3
    if (!PyArg_ParseTupleAndKeywords (args, keywds, "y*|iii", kwlist,
                                    &source,
                                    &head_type,
                                    &max_size,
                                    &return_bytearray))
    {
      return NULL;
    }
#else
  if (!PyArg_ParseTupleAndKeywords (args, keywds, "s*|iii", kwlist,
                                    &source,
                                    &head_type,
                                    &max_size,
                                    &return_bytearray))
    {
      return NULL;
    }
#endif

    switch (head_type) {
    // none
    case 0:
        hdr_size = 0;
        dest_size = source.len;
        break;
    // le32
    case 1:
        hdr_size = sizeof(uint32_t);
        dest_size = load_le32(source.buf);
        break;
    // be32
    case 2:
        hdr_size = sizeof(uint32_t);
        dest_size = load_be32(source.buf);
        break;
    // varint
    case 3:
        hdr_size = VarintParse32WithLimit(source.buf, source.buf + (sizeof(uint32_t)+1), &dest_size) - (const char*)(source.buf);
        break;
    // le32
    default:
        hdr_size = sizeof(uint32_t);
        dest_size = load_le32(source.buf);
        break;
    }

    if (source.len < hdr_size) {
        PyErr_SetString(PyExc_ValueError, "input too short");
        return NULL;
    }

    if (dest_size > INT_MAX) {
        PyErr_Format(PyExc_ValueError, "invalid size in header: 0x%x", dest_size);
        return NULL;
    }
    if (hdr_size == 0) {
        if (max_size ==0 ){
            dest_size = (dest_size < 1024 * 16) ? dest_size * 16: dest_size * 32;
        } else {
            dest_size = max_size;            
        }
    }
    result = PyBytes_FromStringAndSize(NULL, dest_size);
    if (result != NULL && dest_size > 0) {
        char *dest = PyBytes_AS_STRING(result);
        int osize = 0;
        Py_BEGIN_ALLOW_THREADS
        osize = LZ4_decompress_safe(source.buf + hdr_size, dest, source.len - hdr_size, dest_size);
        Py_END_ALLOW_THREADS
        if (osize < 0) {
            if (hdr_size == 0) {
                int rc  = _PyBytes_Resize(&result, dest_size * 2);
                if (rc != 0) {
                    return result;
                }
                dest_size = dest_size * 2;
                Py_BEGIN_ALLOW_THREADS
                osize = LZ4_decompress_safe(source.buf + hdr_size, dest, source.len - hdr_size, dest_size);
                Py_END_ALLOW_THREADS
                if (osize >= 0) {
                    if (osize < (dest_size/ 4) * 3) {
                        _PyBytes_Resize(&result, osize);
                    } else {
                        Py_SIZE(result) = osize;
                    }
                }
            }

            PyErr_Format(PyExc_ValueError, "corrupt input at byte %d", -osize);
            Py_CLEAR(result);
        }
        else if (hdr_size == 0) {
            if (osize < (dest_size/ 4) * 3) {
                _PyBytes_Resize(&result, osize);
            } else {
                Py_SIZE(result) = osize;
            }
        }
    }

    return result;
}

static PyMethodDef Lz4Methods[] = {
    {"LZ4_compress",  py_lz4_compress, METH_VARARGS|METH_KEYWORDS, COMPRESS_DOCSTRING},
    {"LZ4_uncompress",  py_lz4_uncompress, METH_VARARGS|METH_KEYWORDS, UNCOMPRESS_DOCSTRING},
    {"compress",  py_lz4_compress, METH_VARARGS|METH_KEYWORDS, COMPRESS_DOCSTRING},
    {"compressHC",  py_lz4_compressHC, METH_VARARGS|METH_KEYWORDS, COMPRESSHC_DOCSTRING},
    {"uncompress",  py_lz4_uncompress, METH_VARARGS|METH_KEYWORDS, UNCOMPRESS_DOCSTRING},
    {"decompress",  py_lz4_uncompress, METH_VARARGS|METH_KEYWORDS, UNCOMPRESS_DOCSTRING},
    {"dumps",  py_lz4_compress, METH_VARARGS|METH_KEYWORDS, COMPRESS_DOCSTRING},
    {"loads",  py_lz4_uncompress, METH_VARARGS|METH_KEYWORDS, UNCOMPRESS_DOCSTRING},
    {NULL, NULL, 0, NULL}
};



struct module_state {
    PyObject *error;
};

#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct module_state _state;
#endif

#if PY_MAJOR_VERSION >= 3

static int myextension_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int myextension_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}


static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "lz4",
        NULL,
        sizeof(struct module_state),
        Lz4Methods,
        NULL,
        myextension_traverse,
        myextension_clear,
        NULL
};

#define INITERROR return NULL
PyObject *PyInit_lz4(void)

#else
#define INITERROR return
void initlz4(void)

#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject *module = PyModule_Create(&moduledef);
#else
    PyObject *module = Py_InitModule("lz4", Lz4Methods);
#endif
    struct module_state *st = NULL;

    if (module == NULL) {
        INITERROR;
    }
    st = GETSTATE(module);

    st->error = PyErr_NewException("lz4.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    PyModule_AddStringConstant(module, "VERSION", VERSION);
    PyModule_AddStringConstant(module, "__version__", VERSION);
    PyModule_AddStringConstant(module, "LZ4_VERSION", LZ4_VERSION);

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
