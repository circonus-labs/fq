typedef struct {
    int dummy;
} fq_dtrace_msg_t;

typedef struct {
    int dummy;
} fq_msg_t;

typedef struct {
    int dummy;
} fq_dtrace_queue_t;

typedef struct {
    int dummy;
} fq_queue_t;

typedef struct {
    int dummy;
} fq_dtrace_remote_client_t;

typedef struct {
    int dummy;
} fq_remote_client_t;

typedef struct {
    int dummy;
} fq_dtrace_remote_anon_client_t;

typedef struct {
    int dummy;
} fq_remote_anon_client_t;

typedef struct {
    int dummy;
} fq_dtrace_remote_data_client_t;

typedef struct {
    int dummy;
} fq_remote_data_client_t;

provider fq {
    probe client__connect(fq_dtrace_remote_anon_client_t *, int);
    probe client__auth(fq_dtrace_remote_client_t *);
    probe client__auth__data(fq_dtrace_remote_data_client_t *);
    probe client__disconnect(fq_dtrace_remote_anon_client_t *, int);
    probe queue__create__success(int, char *, int, char *, int, int);
    probe queue__create__failure(int, char *, char *);
    probe queue__destroy(int, char *);
    probe queue__drop(fq_dtrace_queue_t *q, fq_dtrace_msg_t *m) :
      (fq_queue_t *q, fq_msg_t *m);
    probe queue__block(fq_dtrace_queue_t *q, fq_dtrace_msg_t *m) :
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
};
