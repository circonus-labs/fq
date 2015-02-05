/* src/jlog/jlog_config.h.  Generated from jlog_config.h.in by configure.  */
/*
 * Copyright (c) 2005-2008, Message Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Message Systems, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __JLOG_CONFIG_H
#define __JLOG_CONFIG_H

/* define inline unless that is what the compiler already calls it. */
/* #undef inline */

#define HAVE_FCNTL_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_DIRENT_H 1
#define HAVE_ERRNO_H 1
#define HAVE_STRING_H 1
#define HAVE_STDLIB_H 1
#define HAVE_UNISTD_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_MMAN_H 1
#define HAVE_TIME_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_INTXX_T 1
/* #undef HAVE_LONG_LONG_INT */
#define HAVE_U_INT 1
#define IFS_CH '/'

#include <sys/time.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* The number of bytes in a char.  */
#define SIZEOF_CHAR 1

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a size_t.  */
/* #undef SIZEOF_SIZE_T */


/* The number of bytes in a long int.  */
#define SIZEOF_LONG_INT 8

/* The number of bytes in a long long int.  */
#define SIZEOF_LONG_LONG_INT 8

/* The number of bytes in a short int.  */
#define SIZEOF_SHORT_INT 2

/* The number of bytes in a void *.  */
#define SIZEOF_VOID_P 8

#ifndef HAVE_U_INT
#define HAVE_U_INT 1
typedef unsigned int u_int;
#endif

#define HAVE_INTXX_T 1
#ifndef HAVE_INTXX_T
#if (SIZEOF_CHAR == 1)
typedef char int8_t;
#else
#error "8 bit int type not found."
#endif
#if (SIZEOF_SHORT_INT == 2)
typedef short int int16_t;
#else
#ifdef _CRAY
typedef long int16_t;
#else
#warning "16 bit int type not found."
#endif /* _CRAY */
#endif
#if (SIZEOF_INT == 4)
typedef int int32_t;
#else
#ifdef _CRAY
typedef long int32_t;
#else
#error "32 bit int type not found."
#endif /* _CRAY */
#endif
#endif

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ifndef HAVE_U_INTXX_T
#ifdef HAVE_UINTXX_T
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
#define HAVE_U_INTXX_T 1
#else
#if (SIZEOF_CHAR == 1)
typedef unsigned char u_int8_t;
#else
#error "8 bit int type not found."
#endif
#if (SIZEOF_SHORT_INT == 2)
typedef unsigned short int u_int16_t;
#else
#ifdef _CRAY
typedef unsigned long u_int16_t;
#else
#warning "16 bit int type not found."
#endif
#endif
#if (SIZEOF_INT == 4)
typedef unsigned int u_int32_t;
#else
#ifdef _CRAY
typedef unsigned long u_int32_t;
#else
#error "32 bit int type not found."
#endif
#endif
#endif
#endif

/* 64-bit types */
#ifndef HAVE_INT64_T
#if (SIZEOF_LONG_INT == 8)
typedef long int int64_t;
#define HAVE_INT64_T 1
#else
#if (SIZEOF_LONG_LONG_INT == 8)
typedef long long int int64_t;
#define HAVE_INT64_T 1
#define HAVE_LONG_LONG_INT
#endif
#endif
#endif
#ifndef HAVE_U_INT64_T
#if (SIZEOF_LONG_INT == 8)
typedef unsigned long int u_int64_t;
#define HAVE_U_INT64_T 1
#else
#if (SIZEOF_LONG_LONG_INT == 8)
typedef unsigned long long int u_int64_t;
#define HAVE_U_INT64_T 1
#endif
#endif
#endif

#endif
