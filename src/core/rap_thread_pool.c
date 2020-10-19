
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_thread_pool.h>


typedef struct {
    rap_array_t               pools;
} rap_thread_pool_conf_t;


typedef struct {
    rap_thread_task_t        *first;
    rap_thread_task_t       **last;
} rap_thread_pool_queue_t;

#define rap_thread_pool_queue_init(q)                                         \
    (q)->first = NULL;                                                        \
    (q)->last = &(q)->first


struct rap_thread_pool_s {
    rap_thread_mutex_t        mtx;
    rap_thread_pool_queue_t   queue;
    rap_int_t                 waiting;
    rap_thread_cond_t         cond;

    rap_log_t                *log;

    rap_str_t                 name;
    rap_uint_t                threads;
    rap_int_t                 max_queue;

    u_char                   *file;
    rap_uint_t                line;
};


static rap_int_t rap_thread_pool_init(rap_thread_pool_t *tp, rap_log_t *log,
    rap_pool_t *pool);
static void rap_thread_pool_destroy(rap_thread_pool_t *tp);
static void rap_thread_pool_exit_handler(void *data, rap_log_t *log);

static void *rap_thread_pool_cycle(void *data);
static void rap_thread_pool_handler(rap_event_t *ev);

static char *rap_thread_pool(rap_conf_t *cf, rap_command_t *cmd, void *conf);

static void *rap_thread_pool_create_conf(rap_cycle_t *cycle);
static char *rap_thread_pool_init_conf(rap_cycle_t *cycle, void *conf);

static rap_int_t rap_thread_pool_init_worker(rap_cycle_t *cycle);
static void rap_thread_pool_exit_worker(rap_cycle_t *cycle);


static rap_command_t  rap_thread_pool_commands[] = {

    { rap_string("thread_pool"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE23,
      rap_thread_pool,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_core_module_t  rap_thread_pool_module_ctx = {
    rap_string("thread_pool"),
    rap_thread_pool_create_conf,
    rap_thread_pool_init_conf
};


rap_module_t  rap_thread_pool_module = {
    RAP_MODULE_V1,
    &rap_thread_pool_module_ctx,           /* module context */
    rap_thread_pool_commands,              /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rap_thread_pool_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    rap_thread_pool_exit_worker,           /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_str_t  rap_thread_pool_default = rap_string("default");

static rap_uint_t               rap_thread_pool_task_id;
static rap_atomic_t             rap_thread_pool_done_lock;
static rap_thread_pool_queue_t  rap_thread_pool_done;


static rap_int_t
rap_thread_pool_init(rap_thread_pool_t *tp, rap_log_t *log, rap_pool_t *pool)
{
    int             err;
    pthread_t       tid;
    rap_uint_t      n;
    pthread_attr_t  attr;

    if (rap_notify == NULL) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
               "the configured event method cannot be used with thread pools");
        return RAP_ERROR;
    }

    rap_thread_pool_queue_init(&tp->queue);

    if (rap_thread_mutex_create(&tp->mtx, log) != RAP_OK) {
        return RAP_ERROR;
    }

    if (rap_thread_cond_create(&tp->cond, log) != RAP_OK) {
        (void) rap_thread_mutex_destroy(&tp->mtx, log);
        return RAP_ERROR;
    }

    tp->log = log;

    err = pthread_attr_init(&attr);
    if (err) {
        rap_log_error(RAP_LOG_ALERT, log, err,
                      "pthread_attr_init() failed");
        return RAP_ERROR;
    }

    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (err) {
        rap_log_error(RAP_LOG_ALERT, log, err,
                      "pthread_attr_setdetachstate() failed");
        return RAP_ERROR;
    }

#if 0
    err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    if (err) {
        rap_log_error(RAP_LOG_ALERT, log, err,
                      "pthread_attr_setstacksize() failed");
        return RAP_ERROR;
    }
#endif

    for (n = 0; n < tp->threads; n++) {
        err = pthread_create(&tid, &attr, rap_thread_pool_cycle, tp);
        if (err) {
            rap_log_error(RAP_LOG_ALERT, log, err,
                          "pthread_create() failed");
            return RAP_ERROR;
        }
    }

    (void) pthread_attr_destroy(&attr);

    return RAP_OK;
}


static void
rap_thread_pool_destroy(rap_thread_pool_t *tp)
{
    rap_uint_t           n;
    rap_thread_task_t    task;
    volatile rap_uint_t  lock;

    rap_memzero(&task, sizeof(rap_thread_task_t));

    task.handler = rap_thread_pool_exit_handler;
    task.ctx = (void *) &lock;

    for (n = 0; n < tp->threads; n++) {
        lock = 1;

        if (rap_thread_task_post(tp, &task) != RAP_OK) {
            return;
        }

        while (lock) {
            rap_sched_yield();
        }

        task.event.active = 0;
    }

    (void) rap_thread_cond_destroy(&tp->cond, tp->log);

    (void) rap_thread_mutex_destroy(&tp->mtx, tp->log);
}


static void
rap_thread_pool_exit_handler(void *data, rap_log_t *log)
{
    rap_uint_t *lock = data;

    *lock = 0;

    pthread_exit(0);
}


rap_thread_task_t *
rap_thread_task_alloc(rap_pool_t *pool, size_t size)
{
    rap_thread_task_t  *task;

    task = rap_pcalloc(pool, sizeof(rap_thread_task_t) + size);
    if (task == NULL) {
        return NULL;
    }

    task->ctx = task + 1;

    return task;
}


rap_int_t
rap_thread_task_post(rap_thread_pool_t *tp, rap_thread_task_t *task)
{
    if (task->event.active) {
        rap_log_error(RAP_LOG_ALERT, tp->log, 0,
                      "task #%ui already active", task->id);
        return RAP_ERROR;
    }

    if (rap_thread_mutex_lock(&tp->mtx, tp->log) != RAP_OK) {
        return RAP_ERROR;
    }

    if (tp->waiting >= tp->max_queue) {
        (void) rap_thread_mutex_unlock(&tp->mtx, tp->log);

        rap_log_error(RAP_LOG_ERR, tp->log, 0,
                      "thread pool \"%V\" queue overflow: %i tasks waiting",
                      &tp->name, tp->waiting);
        return RAP_ERROR;
    }

    task->event.active = 1;

    task->id = rap_thread_pool_task_id++;
    task->next = NULL;

    if (rap_thread_cond_signal(&tp->cond, tp->log) != RAP_OK) {
        (void) rap_thread_mutex_unlock(&tp->mtx, tp->log);
        return RAP_ERROR;
    }

    *tp->queue.last = task;
    tp->queue.last = &task->next;

    tp->waiting++;

    (void) rap_thread_mutex_unlock(&tp->mtx, tp->log);

    rap_log_debug2(RAP_LOG_DEBUG_CORE, tp->log, 0,
                   "task #%ui added to thread pool \"%V\"",
                   task->id, &tp->name);

    return RAP_OK;
}


static void *
rap_thread_pool_cycle(void *data)
{
    rap_thread_pool_t *tp = data;

    int                 err;
    sigset_t            set;
    rap_thread_task_t  *task;

#if 0
    rap_time_update();
#endif

    rap_log_debug1(RAP_LOG_DEBUG_CORE, tp->log, 0,
                   "thread in pool \"%V\" started", &tp->name);

    sigfillset(&set);

    sigdelset(&set, SIGILL);
    sigdelset(&set, SIGFPE);
    sigdelset(&set, SIGSEGV);
    sigdelset(&set, SIGBUS);

    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        rap_log_error(RAP_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
        return NULL;
    }

    for ( ;; ) {
        if (rap_thread_mutex_lock(&tp->mtx, tp->log) != RAP_OK) {
            return NULL;
        }

        /* the number may become negative */
        tp->waiting--;

        while (tp->queue.first == NULL) {
            if (rap_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
                != RAP_OK)
            {
                (void) rap_thread_mutex_unlock(&tp->mtx, tp->log);
                return NULL;
            }
        }

        task = tp->queue.first;
        tp->queue.first = task->next;

        if (tp->queue.first == NULL) {
            tp->queue.last = &tp->queue.first;
        }

        if (rap_thread_mutex_unlock(&tp->mtx, tp->log) != RAP_OK) {
            return NULL;
        }

#if 0
        rap_time_update();
#endif

        rap_log_debug2(RAP_LOG_DEBUG_CORE, tp->log, 0,
                       "run task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->handler(task->ctx, tp->log);

        rap_log_debug2(RAP_LOG_DEBUG_CORE, tp->log, 0,
                       "complete task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->next = NULL;

        rap_spinlock(&rap_thread_pool_done_lock, 1, 2048);

        *rap_thread_pool_done.last = task;
        rap_thread_pool_done.last = &task->next;

        rap_memory_barrier();

        rap_unlock(&rap_thread_pool_done_lock);

        (void) rap_notify(rap_thread_pool_handler);
    }
}


static void
rap_thread_pool_handler(rap_event_t *ev)
{
    rap_event_t        *event;
    rap_thread_task_t  *task;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");

    rap_spinlock(&rap_thread_pool_done_lock, 1, 2048);

    task = rap_thread_pool_done.first;
    rap_thread_pool_done.first = NULL;
    rap_thread_pool_done.last = &rap_thread_pool_done.first;

    rap_memory_barrier();

    rap_unlock(&rap_thread_pool_done_lock);

    while (task) {
        rap_log_debug1(RAP_LOG_DEBUG_CORE, ev->log, 0,
                       "run completion handler for task #%ui", task->id);

        event = &task->event;
        task = task->next;

        event->complete = 1;
        event->active = 0;

        event->handler(event);
    }
}


static void *
rap_thread_pool_create_conf(rap_cycle_t *cycle)
{
    rap_thread_pool_conf_t  *tcf;

    tcf = rap_pcalloc(cycle->pool, sizeof(rap_thread_pool_conf_t));
    if (tcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&tcf->pools, cycle->pool, 4,
                       sizeof(rap_thread_pool_t *))
        != RAP_OK)
    {
        return NULL;
    }

    return tcf;
}


static char *
rap_thread_pool_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_thread_pool_conf_t *tcf = conf;

    rap_uint_t           i;
    rap_thread_pool_t  **tpp;

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->threads) {
            continue;
        }

        if (tpp[i]->name.len == rap_thread_pool_default.len
            && rap_strncmp(tpp[i]->name.data, rap_thread_pool_default.data,
                           rap_thread_pool_default.len)
               == 0)
        {
            tpp[i]->threads = 32;
            tpp[i]->max_queue = 65536;
            continue;
        }

        rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                      "unknown thread pool \"%V\" in %s:%ui",
                      &tpp[i]->name, tpp[i]->file, tpp[i]->line);

        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_thread_pool(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_str_t          *value;
    rap_uint_t          i;
    rap_thread_pool_t  *tp;

    value = cf->args->elts;

    tp = rap_thread_pool_add(cf, &value[1]);

    if (tp == NULL) {
        return RAP_CONF_ERROR;
    }

    if (tp->threads) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "duplicate thread pool \"%V\"", &tp->name);
        return RAP_CONF_ERROR;
    }

    tp->max_queue = 65536;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "threads=", 8) == 0) {

            tp->threads = rap_atoi(value[i].data + 8, value[i].len - 8);

            if (tp->threads == (rap_uint_t) RAP_ERROR || tp->threads == 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid threads value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "max_queue=", 10) == 0) {

            tp->max_queue = rap_atoi(value[i].data + 10, value[i].len - 10);

            if (tp->max_queue == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid max_queue value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }
    }

    if (tp->threads == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"threads\" parameter",
                           &cmd->name);
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


rap_thread_pool_t *
rap_thread_pool_add(rap_conf_t *cf, rap_str_t *name)
{
    rap_thread_pool_t       *tp, **tpp;
    rap_thread_pool_conf_t  *tcf;

    if (name == NULL) {
        name = &rap_thread_pool_default;
    }

    tp = rap_thread_pool_get(cf->cycle, name);

    if (tp) {
        return tp;
    }

    tp = rap_pcalloc(cf->pool, sizeof(rap_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

    tp->name = *name;
    tp->file = cf->conf_file->file.name.data;
    tp->line = cf->conf_file->line;

    tcf = (rap_thread_pool_conf_t *) rap_get_conf(cf->cycle->conf_ctx,
                                                  rap_thread_pool_module);

    tpp = rap_array_push(&tcf->pools);
    if (tpp == NULL) {
        return NULL;
    }

    *tpp = tp;

    return tp;
}


rap_thread_pool_t *
rap_thread_pool_get(rap_cycle_t *cycle, rap_str_t *name)
{
    rap_uint_t                i;
    rap_thread_pool_t       **tpp;
    rap_thread_pool_conf_t   *tcf;

    tcf = (rap_thread_pool_conf_t *) rap_get_conf(cycle->conf_ctx,
                                                  rap_thread_pool_module);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->name.len == name->len
            && rap_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
        {
            return tpp[i];
        }
    }

    return NULL;
}


static rap_int_t
rap_thread_pool_init_worker(rap_cycle_t *cycle)
{
    rap_uint_t                i;
    rap_thread_pool_t       **tpp;
    rap_thread_pool_conf_t   *tcf;

    if (rap_process != RAP_PROCESS_WORKER
        && rap_process != RAP_PROCESS_SINGLE)
    {
        return RAP_OK;
    }

    tcf = (rap_thread_pool_conf_t *) rap_get_conf(cycle->conf_ctx,
                                                  rap_thread_pool_module);

    if (tcf == NULL) {
        return RAP_OK;
    }

    rap_thread_pool_queue_init(&rap_thread_pool_done);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        if (rap_thread_pool_init(tpp[i], cycle->log, cycle->pool) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static void
rap_thread_pool_exit_worker(rap_cycle_t *cycle)
{
    rap_uint_t                i;
    rap_thread_pool_t       **tpp;
    rap_thread_pool_conf_t   *tcf;

    if (rap_process != RAP_PROCESS_WORKER
        && rap_process != RAP_PROCESS_SINGLE)
    {
        return;
    }

    tcf = (rap_thread_pool_conf_t *) rap_get_conf(cycle->conf_ctx,
                                                  rap_thread_pool_module);

    if (tcf == NULL) {
        return;
    }

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        rap_thread_pool_destroy(tpp[i]);
    }
}
