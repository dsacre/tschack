/* -*- mode: c; c-file-style: "bsd"; -*- */
/*
    Copyright (C) 2001-2003 Paul Davis
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef __jack_engine_h__
#define __jack_engine_h__

#include <jack/jack.h>
#include <jack/internal.h>
#include <jack/driver_interface.h>

struct _jack_driver;
struct _jack_client_internal;
struct _jack_port_internal;

/* Structures is allocated by the engine in local memory to keep track
 * of port buffers and connections. 
 */
typedef struct {
    jack_shm_info_t* shm_info;
    jack_shmsize_t   offset;
} jack_port_buffer_info_t;

/* The engine keeps an array of these in its local memory. */
typedef struct _jack_port_internal {
    struct _jack_port_shared *shared;
    JSList                   *connections;
    jack_port_buffer_info_t  *buffer_info;
} jack_port_internal_t;

/* The engine's internal port type structure. */
typedef struct _jack_port_buffer_list {
    pthread_mutex_t          lock;	/* only lock within server */
    JSList	            *freelist;	/* list of free buffers */
    jack_port_buffer_info_t *info;	/* jack_buffer_info_t array */
} jack_port_buffer_list_t;

typedef struct _jack_reserved_name {
    jack_client_id_t uuid;
    char name[JACK_CLIENT_NAME_SIZE];
} jack_reserved_name_t;

#define JACKD_WATCHDOG_TIMEOUT 10000
#define JACKD_CLIENT_EVENT_TIMEOUT 2000

/* The main engine structure in local memory. */
struct _jack_engine {
    jack_control_t        *control;

    JSList                *drivers;
    struct _jack_driver   *driver;
    jack_driver_desc_t    *driver_desc;
    JSList                *driver_params;

    /* these are "callbacks" made by the driver backend */
    int  (*set_buffer_size) (struct _jack_engine *, jack_nframes_t frames);
    int  (*set_sample_rate) (struct _jack_engine *, jack_nframes_t frames);
    int  (*run_cycle)	    (struct _jack_engine *, jack_nframes_t nframes,
			     float delayed_usecs);
    void (*delay)	    (struct _jack_engine *, float delayed_usecs);
    void (*transport_cycle_start) (struct _jack_engine *, jack_time_t time);
    void (*driver_exit)     (struct _jack_engine *);
    jack_time_t (*get_microseconds)(void);
    /* "private" sections starts here */

    /* engine serialization -- use precedence for deadlock avoidance */
    pthread_mutex_t request_lock; /* precedes client_lock */
    pthread_rwlock_t client_lock;
    pthread_mutex_t port_lock;
    pthread_mutexattr_t problem_attr;
    pthread_mutex_t problem_lock; /* must hold write lock on client_lock */
    int		    process_errors;
    int		    period_msecs;

    /* Time to wait for clients in msecs.  Used when jackd is run
     * without realtime priority enabled. */
    int		    client_timeout_msecs;

    /* info on the shm segment containing this->control */

    jack_shm_info_t control_shm;

    /* address-space local port buffer and segment info, 
       indexed by the port type_id 
    */
    jack_port_buffer_list_t port_buffers[JACK_MAX_PORT_TYPES];
    jack_shm_info_t         port_segment[JACK_MAX_PORT_TYPES];

    unsigned int    port_max;
    pthread_t	    server_thread;
    pthread_t	    watchdog_thread;

    int		    fds[2];
    int		    cleanup_fifo[2];
    int		    graph_wait_fd;
    jack_client_id_t next_client_id;
    size_t	    pfd_size;
    size_t	    pfd_max;
    struct pollfd  *pfd;
    char	    fifo_prefix[PATH_MAX+1];
    int		   *fifo;
    unsigned long   fifo_size;

    /* session handling */
    int		    session_reply_fd;
    int		    session_pending_replies;

    unsigned long   external_client_cnt;
    int		    rtpriority;
    volatile char   freewheeling;
    volatile char   stop_freewheeling;
    jack_client_id_t fwclient;
    pthread_t       freewheel_thread;
    char	    verbose;
    char	    do_munlock;
    const char	   *server_name;
    char	    temporary;
    int		    reordered;
    int		    watchdog_check;
    int		    feedbackcount;
    int             removing_clients;
    pid_t           wait_pid;
    int             nozombies;
    int		    jobs;
    int             timeout_count_threshold;
    volatile int    problems;
    volatile int    pending_chain;
    volatile int    timeout_count;
    volatile int    new_clients_allowed;    

    /* these lists are protected by `client_lock' */
    JSList	   *clients;
    JSList	   *reserved_client_names;

    jack_port_internal_t    *internal_ports;
    jack_client_internal_t  *timebase_client;
    jack_port_buffer_info_t *silent_buffer;
    jack_client_internal_t  *current_client;

    /* these lists are protected by the chain locks
     * the RT thread owns one of them, the other is free
     * for manipulation... after manipulation a chainswap
     * needs to be triggered to put the changes in effect.
     */

    JSList	   *process_graph_list[2];
    JSList	   *server_wakeup_list[2];
    _Atomic_word   *client_activation_counts_init[2];
    _Atomic_word   *port_activation_counts_init[2];

    pthread_mutex_t swap_mutex;


#define JACK_ENGINE_ROLLING_COUNT 32
#define JACK_ENGINE_ROLLING_INTERVAL 1024

    jack_time_t rolling_client_usecs[JACK_ENGINE_ROLLING_COUNT];
    int		    rolling_client_usecs_cnt;
    int		    rolling_client_usecs_index;
    int		    rolling_interval;
    float	    max_usecs;
    float	    spare_usecs;

    int first_wakeup;
    
#ifdef JACK_USE_MACH_THREADS
    /* specific resources for server/client real-time thread communication */
    mach_port_t servertask, bp;
    int portnum;
#endif

    /* used for port names munging */
    int audio_out_cnt;
    int audio_in_cnt;
    int midi_out_cnt;
    int midi_in_cnt;


    // methods....

inline int 
jack_rolling_interval (jack_time_t period_usecs);

void
jack_engine_reset_rolling_usecs ();

inline jack_port_type_info_t *
jack_port_type_info (jack_port_internal_t *port);

inline jack_port_buffer_list_t *
jack_port_buffer_list (jack_port_internal_t *port);

int
make_directory (const char *path);

int
make_socket_subdirectories (const char *server_name);

int
make_sockets (const char *server_name, int fd[2]);

void
jack_engine_place_port_buffers (jack_port_type_id_t ptid,
				jack_shmsize_t one_buffer,
				jack_shmsize_t size,
				unsigned long nports,
				jack_nframes_t nframes);


int
jack_resize_port_segment (jack_port_type_id_t ptid,
			  unsigned long nports);

/* The driver invokes this callback both initially and whenever its
 * buffer size changes. 
 */
int
jack_driver_buffer_size (jack_nframes_t nframes);

/* handle client SetBufferSize request */
int
jack_set_buffer_size_request (jack_nframes_t nframes);

#ifdef __linux

/* Linux kernels somewhere between 2.6.18 and 2.6.24 had a bug
   in poll(2) that led poll to return early. To fix it, we need
   to know that that jack_get_microseconds() is monotonic.
*/

#ifdef HAVE_CLOCK_GETTIME
const int system_clock_monotonic = 1;
#else
const int system_clock_monotonic = 0;
#endif

int
linux_poll_bug_encountered (jack_engine_t* engine, jack_time_t then, jack_time_t *required);
#endif


int 
jack_engine_get_execution_token(  );

int 
jack_engine_trigger_client (jack_client_internal_t *client );

int
jack_engine_cleanup_graph_wait (int min_tokens);

int
jack_engine_wait_graph ();
int
jack_engine_process (jack_nframes_t nframes);

void 
jack_calc_cpu_load();

void
jack_engine_post_process ();

#ifdef JACK_USE_MACH_THREADS

int
jack_start_watchdog ();

void
jack_stop_watchdog ();

#else

void *
jack_watchdog_thread (void *arg);

int
jack_start_watchdog ();

void
jack_stop_watchdog ();
#endif /* !JACK_USE_MACH_THREADS */


jack_driver_info_t *
jack_load_driver (jack_driver_desc_t * driver_desc);

void
jack_driver_unload (jack_driver_t *driver);

int
jack_engine_load_driver (jack_driver_desc_t * driver_desc,
			 JSList * driver_params);


/* perform internal or external client request
 *
 * reply_fd is NULL for internal requests
 */
void
do_request (jack_request_t *req, int *reply_fd);

int
internal_client_request (void* ptr, jack_request_t *request);

int
handle_external_client_request (int fd);

int
handle_client_ack_connection (int client_fd);


void *
jack_server_thread (void *arg);


jack_engine_t *
jack_engine_new (int realtime, int rtpriority, int do_mlock, int do_unlock,
		 const char *server_name, int temporary, int verbose,
		 int client_timeout, unsigned int port_max, pid_t wait_pid,
		 jack_nframes_t frame_time_offset, int nozombies, int timeout_count_threshold, int jobs, JSList *drivers);

void
jack_engine_delay (float delayed_usecs);

inline void
jack_inc_frame_time (jack_nframes_t nframes);

void*
jack_engine_freewheel (void *arg);

int
jack_start_freewheeling (jack_engine_t* engine, jack_client_id_t client_id);

int
jack_stop_freewheeling (jack_engine_t* engine, int engine_exiting);

int
jack_check_client_status (jack_engine_t* engine);

int
jack_run_one_cycle (jack_nframes_t nframes,
		    float delayed_usecs);

void
jack_engine_driver_exit (jack_engine_t* engine);

int
jack_run_cycle (jack_nframes_t nframes,
		float delayed_usecs);

void 
jack_engine_delete ();

void
jack_port_clear_connections (jack_port_internal_t *port);

void
jack_deliver_event_to_all (jack_event_t *event);

jack_client_id_t jack_engine_get_max_uuid(  );

void jack_do_get_client_by_uuid ( jack_request_t *req);

void jack_do_reserve_name ( jack_request_t *req);

int jack_send_session_reply ( jack_client_internal_t *client );

int
jack_do_session_notify (jack_request_t *req, int reply_fd );

void jack_do_session_reply (jack_request_t *req );

void
jack_notify_all_port_interested_clients (jack_client_id_t src, jack_client_id_t dst, jack_port_id_t a, jack_port_id_t b, int connected);

void
jack_driver_do_reorder( jack_client_t *client, jack_event_t *event );
int
jack_deliver_event (jack_client_internal_t *client,
		    jack_event_t *event);

int
jack_rechain_graph ();

jack_nframes_t
jack_get_port_total_latency (jack_port_internal_t *port, int hop_count,
			     int toward_port);

void
jack_compute_port_total_latency (jack_engine_t* engine, jack_port_shared_t* port);

void
jack_compute_all_port_total_latencies ();

void
jack_sort_graph ();

int 
jack_client_sort (jack_client_internal_t *a, jack_client_internal_t *b);

/* transitive closure of the relation expressed by the sortfeeds lists. */
int
jack_client_feeds_transitive (jack_client_internal_t *source,
			      jack_client_internal_t *dest );

/**
 * Checks whether the graph has become acyclic and if so modifies client
 * sortfeeds lists to turn leftover feedback connections into normal ones.
 * This lowers latency, but at the expense of some data corruption.
 */
void
jack_check_acyclic ();

/**
 * Dumps current engine configuration.
 */
void jack_dump_configuration(int take_lock);

int 
jack_port_do_connect (const char *source_port,
		       const char *destination_port);

int
jack_port_disconnect_internal (
			       jack_port_internal_t *srcport, 
			       jack_port_internal_t *dstport );


int
jack_port_do_disconnect_all (jack_port_id_t port_id);

int 
jack_port_do_disconnect (const char *source_port,
			 const char *destination_port);

int 
jack_get_fifo_fd (unsigned int which_fifo);

void
jack_clear_fifos ();

int
jack_use_driver (jack_driver_t *driver);


/* PORT RELATED FUNCTIONS */


jack_port_id_t
jack_get_free_port ();

void
jack_port_release (jack_port_internal_t *port);

jack_port_internal_t *
jack_get_port_internal_by_name (const char *name);

int
jack_port_do_register (jack_request_t *req, int internal);

int
jack_port_do_unregister (jack_request_t *req);

int
jack_do_get_port_connections (jack_request_t *req,
			      int reply_fd);

void
jack_port_registration_notify (jack_port_id_t port_id, int yn);

void
jack_client_registration_notify (const char* name, int yn);

int
jack_port_assign_buffer (jack_port_internal_t *port);

jack_port_internal_t *
jack_get_port_by_name (const char *name);

int
jack_send_connection_notification (jack_client_id_t client_id, 
				   jack_port_id_t self_id,
				   jack_port_id_t other_id, int connected);


void
jack_wake_server_thread ();

void
jack_engine_signal_problems ();

};


#define jack_rdlock_graph(e) { DEBUG ("acquiring graph read lock"); if (pthread_rwlock_rdlock (&e->client_lock)) abort(); }
#define jack_lock_graph(e) { DEBUG ("acquiring graph write lock"); if (pthread_rwlock_wrlock (&e->client_lock)) abort(); }
#define jack_try_rdlock_graph(e) pthread_rwlock_tryrdlock (&e->client_lock)
#define jack_unlock_graph(e) { DEBUG ("release graph lock"); if (pthread_rwlock_unlock (&e->client_lock)) abort(); }

#define jack_trylock_problems(e) pthread_mutex_trylock (&e->problem_lock)
#define jack_lock_problems(e) { DEBUG ("acquiring problem lock"); if (pthread_mutex_lock (&e->problem_lock)) abort(); }
#define jack_unlock_problems(e) { DEBUG ("release problem lock"); if (pthread_mutex_unlock (&e->problem_lock)) abort(); }

#if 0
static inline void jack_rdlock_graph (jack_engine_t* engine) {
	DEBUG ("acquiring graph read lock");
	pthread_rwlock_rdlock (&engine->client_lock);
}

static inline void jack_lock_graph (jack_engine_t* engine) {
	DEBUG ("acquiring graph lock");
	pthread_rwlock_wrlock (&engine->client_lock);
}

static inline int jack_try_rdlock_graph (jack_engine_t *engine)
{
	DEBUG ("TRYING to acquiring graph read lock");
	return pthread_rwlock_tryrdlock (&engine->client_lock);
}

static inline void jack_unlock_graph (jack_engine_t* engine) 
{
	DEBUG ("releasing graph lock");
	pthread_rwlock_unlock (&engine->client_lock);
}
#endif

static inline unsigned int jack_power_of_two (unsigned int n)
{
	return !(n & (n - 1));
}


typedef struct {

    jack_port_internal_t *source;
    jack_port_internal_t *destination;
    signed int dir; /* -1 = feedback, 0 = self, 1 = forward */
    jack_client_internal_t *srcclient;
    jack_client_internal_t *dstclient;
} jack_connection_internal_t;

typedef struct _jack_driver_info {
    jack_driver_t *(*initialize)(jack_client_t*, const JSList *);
    void           (*finish);
    char           (*client_name);
    dlhandle       handle;
} jack_driver_info_t;

jack_timer_type_t clock_source = JACK_TIMER_SYSTEM_CLOCK;
#endif /* __jack_engine_h__ */
