/*
 * Copyright (c) 2013 OmniTI Computer Consulting, Inc.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

provider fq {
    probe client__connect(fq_dtrace_remote_anon_client_t *c, int m) :
      (fq_remote_anon_client_t *c, int m);
    probe client__disconnect(fq_dtrace_remote_anon_client_t *c, int m) :
      (fq_remote_anon_client_t *c, int m);
    probe client__auth(fq_dtrace_remote_client_t *c) :
      (fq_remote_client_t *c);
    probe client__auth__data(fq_dtrace_remote_data_client_t *c) :
      (fq_remote_data_client_t *c);
    probe queue__create__success(int, char *, int, char *, int, int);
    probe queue__create__failure(int, char *, char *);
    probe queue__destroy(int, char *);
    probe queue__drop(fq_dtrace_queue_t *q, fq_dtrace_msg_t *m) :
      (fq_queue_t *q, fq_msg_t *m);
    probe queue__block(fq_dtrace_queue_t *q, fq_dtrace_msg_t *m) :
      (fq_queue_t *q, fq_msg_t *m);
    probe queue__enqueue(fq_dtrace_queue_t *q, fq_dtrace_msg_t *m) :
      (fq_queue_t *q, fq_msg_t *m);
    probe config__rotate(int);
    probe message__receive(fq_dtrace_remote_client_t *c,
                           fq_dtrace_remote_data_client_t *d,
                           fq_dtrace_msg_t *m) :
      (fq_remote_client_t *c,
       fq_remote_data_client_t *d,
       fq_msg_t *m);
    probe message__deliver(fq_dtrace_remote_client_t *c,
                           fq_dtrace_remote_data_client_t *d,
                           fq_dtrace_msg_t *m) :
      (fq_remote_client_t *c,
       fq_remote_data_client_t *d,
       fq_msg_t *m);
    probe route__program__entry(char *p, fq_dtrace_msg_t *m) :
      (char *p, fq_msg_t *m);
    probe route__program__return(char *p, fq_dtrace_msg_t *m, int32_t u) :
      (char *p, fq_msg_t *m, int32_t u);
};

#pragma D attributes Evolving/Evolving/ISA provider fq provider
#pragma D attributes Private/Private/Unknown provider fq module
#pragma D attributes Private/Private/Unknown provider fq function
#pragma D attributes Private/Private/ISA provider fq name
#pragma D attributes Evolving/Evolving/ISA provider fq args
