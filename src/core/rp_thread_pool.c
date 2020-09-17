
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_thread_pool.h>


typedef struct {
    rp_array_t               pools;
} rp_thread_pool_conf_t;


typedef struct {
    rp_thread_task_t        *first;
    rp_thread_task_t       **last;
} rp_thread_pool_queue_t;

#define rp_thread_pool_queue_init(q)                                         \
    (q)->first = NULL;                                                        \
    (q)->last = &(q)->first


struct rp_thread_pool_s {
    rp_thread_mutex_t        mtx;
    rp_thread_pool_queue_t   queue;
    rp_int_t                 waiting;
    rp_thread_cond_t         cond;

    rp_log_t                *log;

    rp_str_t                 name;
    rp_uint_t                threads;
    rp_int_t                 max_queue;

    u_char                   *file;
    rp_uint_t                line;
};


static rp_int_t rp_thread_pool_init(rp_thread_pool_t *tp, rp_log_t *log,
    rp_pool_t *pool);
static void rp_thread_pool_destroy(rp_thread_pool_t *tp);
static void rp_thread_pool_exit_handler(void *data, rp_log_t *log);

static void *rp_thread_pool_cycle(void *data);
static void rp_thread_pool_handler(rp_event_t *ev);

static char *rp_thread_pool(rp_conf_t *cf, rp_command_t *cmd, void *conf);

static void *rp_thread_pool_create_conf(rp_cycle_t *cycle);
static char *rp_thread_pool_init_conf(rp_cycle_t *cycle, void *conf);

static rp_int_t rp_thread_pool_init_worker(rp_cycle_t *cycle);
static void rp_thread_pool_exit_worker(rp_cycle_t *cycle);


static rp_command_t  rp_thread_pool_commands[] = {

    { rp_string("thread_pool"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE23,
      rp_thread_pool,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_thread_pool_module_ctx = {
    rp_string("thread_pool"),
    rp_thread_pool_create_conf,
    rp_thread_pool_init_conf
};


rp_module_t  rp_thread_pool_module = {
    RP_MODULE_V1,
    &rp_thread_pool_module_ctx,           /* module context */
    rp_thread_pool_commands,              /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rp_thread_pool_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    rp_thread_pool_exit_worker,           /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t  rp_thread_pool_default = rp_string("default");

static rp_uint_t               rp_thread_pool_task_id;
static rp_atomic_t             rp_thread_pool_done_lock;
static rp_thread_pool_queue_t  rp_thread_pool_done;


static rp_int_t
rp_thread_pool_init(rp_thread_pool_t *tp, rp_log_t *log, rp_pool_t *pool)
{
    int             err;
    pthread_t       tid;
    rp_uint_t      n;
    pthread_attr_t  attr;

    if (rp_notify == NULL) {
        rp_log_error(RP_LOG_ALERT, log, 0,
               "the configured event method cannot be used with thread pools");
        return RP_ERROR;
    }

    rp_thread_pool_queue_init(&tp->queue);

    if (rp_thread_mutex_create(&tp->mtx, log) != RP_OK) {
        return RP_ERROR;
    }

    if (rp_thread_cond_create(&tp->cond, log) != RP_OK) {
        (void) rp_thread_mutex_destroy(&tp->mtx, log);
        return RP_ERROR;
    }

    tp->log = log;

    err = pthread_attr_init(&attr);
    if (err) {
        rp_log_error(RP_LOG_ALERT, log, err,
                      "pthread_attr_init() failed");
        return RP_ERROR;
    }

    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (err) {
        rp_log_error(RP_LOG_ALERT, log, err,
                      "pthread_attr_setdetachstate() failed");
        return RP_ERROR;
    }

#if 0
    err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    if (err) {
        rp_log_error(RP_LOG_ALERT, log, err,
                      "pthread_attr_setstacksize() failed");
        return RP_ERROR;
    }
#endif

    for (n = 0; n < tp->threads; n++) {
        err = pthread_create(&tid, &attr, rp_thread_pool_cycle, tp);
        if (err) {
            rp_log_error(RP_LOG_ALERT, log, err,
                          "pthread_create() failed");
            return RP_ERROR;
        }
    }

    (void) pthread_attr_destroy(&attr);

    return RP_OK;
}


static void
rp_thread_pool_destroy(rp_thread_pool_t *tp)
{
    rp_uint_t           n;
    rp_thread_task_t    task;
    volatile rp_uint_t  lock;

    rp_memzero(&task, sizeof(rp_thread_task_t));

    task.handler = rp_thread_pool_exit_handler;
    task.ctx = (void *) &lock;

    for (n = 0; n < tp->threads; n++) {
        lock = 1;

        if (rp_thread_task_post(tp, &task) != RP_OK) {
            return;
        }

        while (lock) {
            rp_sched_yield();
        }

        task.event.active = 0;
    }

    (void) rp_thread_cond_destroy(&tp->cond, tp->log);

    (void) rp_thread_mutex_destroy(&tp->mtx, tp->log);
}


static void
rp_thread_pool_exit_handler(void *data, rp_log_t *log)
{
    rp_uint_t *lock = data;

    *lock = 0;

    pthread_exit(0);
}


rp_thread_task_t *
rp_thread_task_alloc(rp_pool_t *pool, size_t size)
{
    rp_thread_task_t  *task;

    task = rp_pcalloc(pool, sizeof(rp_thread_task_t) + size);
    if (task == NULL) {
        return NULL;
    }

    task->ctx = task + 1;

    return task;
}


rp_int_t
rp_thread_task_post(rp_thread_pool_t *tp, rp_thread_task_t *task)
{
    if (task->event.active) {
        rp_log_error(RP_LOG_ALERT, tp->log, 0,
                      "task #%ui already active", task->id);
        return RP_ERROR;
    }

    if (rp_thread_mutex_lock(&tp->mtx, tp->log) != RP_OK) {
        return RP_ERROR;
    }

    if (tp->waiting >= tp->max_queue) {
        (void) rp_thread_mutex_unlock(&tp->mtx, tp->log);

        rp_log_error(RP_LOG_ERR, tp->log, 0,
                      "thread pool \"%V\" queue overflow: %i tasks waiting",
                      &tp->name, tp->waiting);
        return RP_ERROR;
    }

    task->event.active = 1;

    task->id = rp_thread_pool_task_id++;
    task->next = NULL;

    if (rp_thread_cond_signal(&tp->cond, tp->log) != RP_OK) {
        (void) rp_thread_mutex_unlock(&tp->mtx, tp->log);
        return RP_ERROR;
    }

    *tp->queue.last = task;
    tp->queue.last = &task->next;

    tp->waiting++;

    (void) rp_thread_mutex_unlock(&tp->mtx, tp->log);

    rp_log_debug2(RP_LOG_DEBUG_CORE, tp->log, 0,
                   "task #%ui added to thread pool \"%V\"",
                   task->id, &tp->name);

    return RP_OK;
}


static void *
rp_thread_pool_cycle(void *data)
{
    rp_thread_pool_t *tp = data;

    int                 err;
    sigset_t            set;
    rp_thread_task_t  *task;

#if 0
    rp_time_update();
#endif

    rp_log_debug1(RP_LOG_DEBUG_CORE, tp->log, 0,
                   "thread in pool \"%V\" started", &tp->name);

    sigfillset(&set);

    sigdelset(&set, SIGILL);
    sigdelset(&set, SIGFPE);
    sigdelset(&set, SIGSEGV);
    sigdelset(&set, SIGBUS);

    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        rp_log_error(RP_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
        return NULL;
    }

    for ( ;; ) {
        if (rp_thread_mutex_lock(&tp->mtx, tp->log) != RP_OK) {
            return NULL;
        }

        /* the number may become negative */
        tp->waiting--;

        while (tp->queue.first == NULL) {
            if (rp_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
                != RP_OK)
            {
                (void) rp_thread_mutex_unlock(&tp->mtx, tp->log);
                return NULL;
            }
        }

        task = tp->queue.first;
        tp->queue.first = task->next;

        if (tp->queue.first == NULL) {
            tp->queue.last = &tp->queue.first;
        }

        if (rp_thread_mutex_unlock(&tp->mtx, tp->log) != RP_OK) {
            return NULL;
        }

#if 0
        rp_time_update();
#endif

        rp_log_debug2(RP_LOG_DEBUG_CORE, tp->log, 0,
                       "run task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->handler(task->ctx, tp->log);

        rp_log_debug2(RP_LOG_DEBUG_CORE, tp->log, 0,
                       "complete task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->next = NULL;

        rp_spinlock(&rp_thread_pool_done_lock, 1, 2048);

        *rp_thread_pool_done.last = task;
        rp_thread_pool_done.last = &task->next;

        rp_memory_barrier();

        rp_unlock(&rp_thread_pool_done_lock);

        (void) rp_notify(rp_thread_pool_handler);
    }
}


static void
rp_thread_pool_handler(rp_event_t *ev)
{
    rp_event_t        *event;
    rp_thread_task_t  *task;

    rp_log_debug0(RP_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");

    rp_spinlock(&rp_thread_pool_done_lock, 1, 2048);

    task = rp_thread_pool_done.first;
    rp_thread_pool_done.first = NULL;
    rp_thread_pool_done.last = &rp_thread_pool_done.first;

    rp_memory_barrier();

    rp_unlock(&rp_thread_pool_done_lock);

    while (task) {
        rp_log_debug1(RP_LOG_DEBUG_CORE, ev->log, 0,
                       "run completion handler for task #%ui", task->id);

        event = &task->event;
        task = task->next;

        event->complete = 1;
        event->active = 0;

        event->handler(event);
    }
}


static void *
rp_thread_pool_create_conf(rp_cycle_t *cycle)
{
    rp_thread_pool_conf_t  *tcf;

    tcf = rp_pcalloc(cycle->pool, sizeof(rp_thread_pool_conf_t));
    if (tcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&tcf->pools, cycle->pool, 4,
                       sizeof(rp_thread_pool_t *))
        != RP_OK)
    {
        return NULL;
    }

    return tcf;
}


static char *
rp_thread_pool_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_thread_pool_conf_t *tcf = conf;

    rp_uint_t           i;
    rp_thread_pool_t  **tpp;

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->threads) {
            continue;
        }

        if (tpp[i]->name.len == rp_thread_pool_default.len
            && rp_strncmp(tpp[i]->name.data, rp_thread_pool_default.data,
                           rp_thread_pool_default.len)
               == 0)
        {
            tpp[i]->threads = 32;
            tpp[i]->max_queue = 65536;
            continue;
        }

        rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                      "unknown thread pool \"%V\" in %s:%ui",
                      &tpp[i]->name, tpp[i]->file, tpp[i]->line);

        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_thread_pool(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_str_t          *value;
    rp_uint_t          i;
    rp_thread_pool_t  *tp;

    value = cf->args->elts;

    tp = rp_thread_pool_add(cf, &value[1]);

    if (tp == NULL) {
        return RP_CONF_ERROR;
    }

    if (tp->threads) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "duplicate thread pool \"%V\"", &tp->name);
        return RP_CONF_ERROR;
    }

    tp->max_queue = 65536;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "threads=", 8) == 0) {

            tp->threads = rp_atoi(value[i].data + 8, value[i].len - 8);

            if (tp->threads == (rp_uint_t) RP_ERROR || tp->threads == 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid threads value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "max_queue=", 10) == 0) {

            tp->max_queue = rp_atoi(value[i].data + 10, value[i].len - 10);

            if (tp->max_queue == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid max_queue value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }
    }

    if (tp->threads == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"threads\" parameter",
                           &cmd->name);
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


rp_thread_pool_t *
rp_thread_pool_add(rp_conf_t *cf, rp_str_t *name)
{
    rp_thread_pool_t       *tp, **tpp;
    rp_thread_pool_conf_t  *tcf;

    if (name == NULL) {
        name = &rp_thread_pool_default;
    }

    tp = rp_thread_pool_get(cf->cycle, name);

    if (tp) {
        return tp;
    }

    tp = rp_pcalloc(cf->pool, sizeof(rp_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

    tp->name = *name;
    tp->file = cf->conf_file->file.name.data;
    tp->line = cf->conf_file->line;

    tcf = (rp_thread_pool_conf_t *) rp_get_conf(cf->cycle->conf_ctx,
                                                  rp_thread_pool_module);

    tpp = rp_array_push(&tcf->pools);
    if (tpp == NULL) {
        return NULL;
    }

    *tpp = tp;

    return tp;
}


rp_thread_pool_t *
rp_thread_pool_get(rp_cycle_t *cycle, rp_str_t *name)
{
    rp_uint_t                i;
    rp_thread_pool_t       **tpp;
    rp_thread_pool_conf_t   *tcf;

    tcf = (rp_thread_pool_conf_t *) rp_get_conf(cycle->conf_ctx,
                                                  rp_thread_pool_module);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->name.len == name->len
            && rp_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
        {
            return tpp[i];
        }
    }

    return NULL;
}


static rp_int_t
rp_thread_pool_init_worker(rp_cycle_t *cycle)
{
    rp_uint_t                i;
    rp_thread_pool_t       **tpp;
    rp_thread_pool_conf_t   *tcf;

    if (rp_process != RP_PROCESS_WORKER
        && rp_process != RP_PROCESS_SINGLE)
    {
        return RP_OK;
    }

    tcf = (rp_thread_pool_conf_t *) rp_get_conf(cycle->conf_ctx,
                                                  rp_thread_pool_module);

    if (tcf == NULL) {
        return RP_OK;
    }

    rp_thread_pool_queue_init(&rp_thread_pool_done);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        if (rp_thread_pool_init(tpp[i], cycle->log, cycle->pool) != RP_OK) {
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static void
rp_thread_pool_exit_worker(rp_cycle_t *cycle)
{
    rp_uint_t                i;
    rp_thread_pool_t       **tpp;
    rp_thread_pool_conf_t   *tcf;

    if (rp_process != RP_PROCESS_WORKER
        && rp_process != RP_PROCESS_SINGLE)
    {
        return;
    }

    tcf = (rp_thread_pool_conf_t *) rp_get_conf(cycle->conf_ctx,
                                                  rp_thread_pool_module);

    if (tcf == NULL) {
        return;
    }

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        rp_thread_pool_destroy(tpp[i]);
    }
}
