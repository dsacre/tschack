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

struct jack_driver_t;
struct jack_client_internal_t;
struct jack_port_internal_t;

struct jack_driver_info_t {
    jack_driver_t *(*initialize)(jack_client_t*, const JSList *);
    void           (*finish);
    char           (*client_name);
    dlhandle       handle;
};
/* Structures is allocated by the engine in local memory to keep track
 * of port buffers and connections. 
 */
struct jack_port_buffer_info_t {
    jack_shm_info_t* shm_info;
    jack_shmsize_t   offset;
};

/* The engine keeps an array of these in its local memory. */
struct jack_port_internal_t {
    struct _jack_port_shared *shared;
    JSList                   *connections;
    jack_port_buffer_info_t  *buffer_info;
};

/* The engine's internal port type structure. */
struct jack_port_buffer_list_t {
    pthread_mutex_t          lock;	/* only lock within server */
    JSList	            *freelist;	/* list of free buffers */
    jack_port_buffer_info_t *info;	/* jack_buffer_info_t array */
};

struct jack_reserved_name_t {
    jack_client_id_t uuid;
    char name[JACK_CLIENT_NAME_SIZE];
};

#define JACKD_WATCHDOG_TIMEOUT 10000
#define JACKD_CLIENT_EVENT_TIMEOUT 2000

/* The main engine structure in local memory. */
struct jack_engine_t {
    jack_control_t        *_control;

    JSList                *_drivers;
    jack_driver_t   *_driver;
    jack_driver_desc_t    *_driver_desc;
    JSList                *_driver_params;

    /* these are "callbacks" made by the driver backend */
    int  (*_set_buffer_size) (jack_engine_t *, jack_nframes_t frames);
    int  (*_set_sample_rate) (jack_engine_t *, jack_nframes_t frames);
    int  (*_run_cycle)	    (jack_engine_t *, jack_nframes_t nframes,
			     float delayed_usecs);
    void (*_delay)	    (jack_engine_t *, float delayed_usecs);
    void (*_transport_cycle_start) (jack_engine_t *, jack_time_t time);
    void (*_driver_exit)     (jack_engine_t *);
    jack_time_t (*_get_microseconds)(void);
    /* "private" sections starts here */

    /* engine serialization -- use precedence for deadlock avoidance */
    pthread_mutex_t _request_lock; /* precedes client_lock */
    pthread_rwlock_t _client_lock;
    pthread_mutex_t _port_lock;
    pthread_mutexattr_t _problem_attr;
    pthread_mutex_t _problem_lock; /* must hold write lock on client_lock */
    int		    _process_errors;
    int		    _period_msecs;

    /* Time to wait for clients in msecs.  Used when jackd is run
     * without realtime priority enabled. */
    int		    _client_timeout_msecs;

    /* info on the shm segment containing this->control */

    jack_shm_info_t _control_shm;

    /* address-space local port buffer and segment info, 
       indexed by the port type_id 
    */
    jack_port_buffer_list_t _port_buffers[JACK_MAX_PORT_TYPES];
    jack_shm_info_t         _port_segment[JACK_MAX_PORT_TYPES];

    unsigned int    _port_max;
    pthread_t	    _server_thread;
    pthread_t	    _watchdog_thread;

    int		    _fds[2];
    int		    _cleanup_fifo[2];
    int		    _graph_wait_fd;
    jack_client_id_t _next_client_id;
    size_t	    _pfd_size;
    size_t	    _pfd_max;
    struct pollfd  *_pfd;
    char	    _fifo_prefix[PATH_MAX+1];
    int		   *_fifo;
    unsigned long   _fifo_size;

    /* session handling */
    int		    _session_reply_fd;
    int		    _session_pending_replies;

    unsigned long   _external_client_cnt;
    int		    _rtpriority;
    volatile char   _freewheeling;
    volatile char   _stop_freewheeling;
    jack_client_id_t _fwclient;
    pthread_t       _freewheel_thread;
    char	    _verbose;
    char	    _do_munlock;
    const char	   *_server_name;
    char	    _temporary;
    int		    _reordered;
    int		    _watchdog_check;
    int		    _feedbackcount;
    int             _removing_clients;
    pid_t           _wait_pid;
    int             _nozombies;
    int		    _jobs;
    int             _timeout_count_threshold;
    volatile int    _problems;
    volatile int    _pending_chain;
    volatile int    _timeout_count;
    volatile int    _new_clients_allowed;    

    /* these lists are protected by `client_lock' */
    JSList	   *_clients;
    JSList	   *_reserved_client_names;

    jack_port_internal_t    *_internal_ports;
    jack_client_internal_t  *_timebase_client;
    jack_port_buffer_info_t *_silent_buffer;
    jack_client_internal_t  *_current_client;

    /* these lists are protected by the chain locks
     * the RT thread owns one of them, the other is free
     * for manipulation... after manipulation a chainswap
     * needs to be triggered to put the changes in effect.
     */

    JSList	   *_process_graph_list[2];
    JSList	   *_server_wakeup_list[2];
    _Atomic_word   *_client_activation_counts_init[2];
    _Atomic_word   *_port_activation_counts_init[2];

    pthread_mutex_t _swap_mutex;


#define JACK_ENGINE_ROLLING_COUNT 32
#define JACK_ENGINE_ROLLING_INTERVAL 1024

    jack_time_t _rolling_client_usecs[JACK_ENGINE_ROLLING_COUNT];
    int		    _rolling_client_usecs_cnt;
    int		    _rolling_client_usecs_index;
    int		    _rolling_interval;
    float	    _max_usecs;
    float	    _spare_usecs;

    int _first_wakeup;
    
#ifdef JACK_USE_MACH_THREADS
    /* specific resources for server/client real-time thread communication */
    mach_port_t _servertask, _bp;
    int _portnum;
#endif

    /* used for port names munging */
    int _audio_out_cnt;
    int _audio_in_cnt;
    int _midi_out_cnt;
    int _midi_in_cnt;


    // methods....

int 
jack_rolling_interval (jack_time_t period_usecs);

void
jack_engine_reset_rolling_usecs ();

jack_port_type_info_t *
jack_port_type_info (jack_port_internal_t *port);

jack_port_buffer_list_t *
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

static int
jack_driver_buffer_size_aux (jack_engine_t *engine, jack_nframes_t nframes);

/* handle client SetBufferSize request */
int
jack_set_buffer_size_request (jack_nframes_t nframes);

#ifdef __linux

/* Linux kernels somewhere between 2.6.18 and 2.6.24 had a bug
   in poll(2) that led poll to return early. To fix it, we need
   to know that that jack_get_microseconds() is monotonic.
*/

#ifdef HAVE_CLOCK_GETTIME
static const int system_clock_monotonic;
#else
static const int system_clock_monotonic;
#endif

int
linux_poll_bug_encountered (jack_time_t then, jack_time_t *required);
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

static void *
jack_watchdog_thread_aux (void *arg);

void *
jack_watchdog_thread ();

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


/* some wrapped callbacks here.
 *
 */

static int
jack_set_sample_rate_aux (jack_engine_t *engine, jack_nframes_t nframes);

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
jack_server_thread ();

static void *
jack_server_thread_aux (void *arg);

jack_engine_t   (int realtime, int rtpriority, int do_mlock, int do_unlock,
		 const char *server_name, int temporary, int verbose,
		 int client_timeout, unsigned int port_max, pid_t wait_pid,
		 jack_nframes_t frame_time_offset, int nozombies, int timeout_count_threshold, int jobs, JSList *drivers);

~jack_engine_t ();

void
jack_engine_delay (float delayed_usecs);

static void
jack_engine_delay_aux (jack_engine_t *engine, float delayed_usecs);

inline void
jack_inc_frame_time (jack_nframes_t nframes);

void*
jack_engine_freewheel ();
static void*
jack_engine_freewheel_aux (void *arg);

int
jack_start_freewheeling (jack_client_id_t client_id);

int
jack_stop_freewheeling (int engine_exiting);

int
jack_check_client_status ();

int
jack_run_one_cycle (jack_nframes_t nframes,
		    float delayed_usecs);

void
jack_engine_driver_exit ();

static void
jack_engine_driver_exit_aux (jack_engine_t *engine);

int
jack_run_cycle (jack_nframes_t nframes,
		float delayed_usecs);

static int
jack_run_cycle_aux (jack_engine_t *engine, jack_nframes_t nframes, float delayed_usecs);

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
jack_compute_port_total_latency (jack_port_shared_t* port);

void
jack_compute_all_port_total_latencies ();

void
jack_sort_graph ();

static int 
jack_client_sort (jack_client_internal_t *a, jack_client_internal_t *b);

/* transitive closure of the relation expressed by the sortfeeds lists. */
static int
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


/*
 * methods from client engine now.
 */


void
jack_client_disconnect_ports (
			      jack_client_internal_t *client);

int
jack_client_do_deactivate (
			   jack_client_internal_t *client, int sort_graph);

static int
jack_load_client ( jack_client_internal_t *client,
		  const char *so_name);

static void
jack_client_unload (jack_client_internal_t *client);

static void
jack_zombify_client ( jack_client_internal_t *client);

void
jack_remove_client ( jack_client_internal_t *client);

int
jack_check_clients ( int with_timeout_check);

void
jack_remove_clients ( int* exit_freewheeling_when_done);

jack_client_internal_t *
jack_client_by_name ( const char *name);

static jack_client_id_t
jack_client_id_by_name ( const char *name);

jack_client_internal_t *
jack_client_internal_by_id ( jack_client_id_t id);

int
jack_client_name_reserved(  const char *name );

/* generate a unique client name
 *
 * returns 0 if successful, updates name in place
 */
static inline int
jack_generate_unique_name ( char *name);

static int
jack_client_name_invalid ( char *name,
			  jack_options_t options, jack_status_t *status);

static jack_client_id_t
jack_get_client_id( jack_engine_t *engine );

/* Set up the engine's client internal and control structures for both
 * internal and external clients. */
static jack_client_internal_t *
jack_setup_client_control ( int fd,
			   ClientType type, const char *name, jack_client_id_t uuid);

static void
jack_ensure_uuid_unique ( jack_client_id_t uuid);

/* set up all types of clients */
static jack_client_internal_t *
setup_client ( ClientType type, char *name, jack_client_id_t uuid,
	      jack_options_t options, jack_status_t *status, int client_fd,
	      const char *object_path, const char *object_data);

jack_client_internal_t *
jack_create_driver_client ( char *name);

static jack_status_t
handle_unload_client ( jack_client_id_t id);

static char *
jack_get_reserved_name(  jack_client_id_t uuid );

int
jack_client_create ( int client_fd);

int
jack_client_activate ( jack_client_id_t id);

int
jack_client_deactivate ( jack_client_id_t id);

jack_client_internal_t *
jack_get_client_for_fd ( int fd);

int
jack_mark_client_socket_error ( int fd);

void
jack_client_delete ( jack_client_internal_t *client);

void
jack_intclient_handle_request ( jack_request_t *req);

void
jack_intclient_load_request ( jack_request_t *req);

void
jack_intclient_name_request ( jack_request_t *req);

void
jack_intclient_unload_request ( jack_request_t *req);





/*
 * transportengine.c
 */

/* initiate polling a new slow-sync client
 *
 *   precondition: caller holds the graph lock. */
static inline void
jack_sync_poll_new ( jack_client_internal_t *client);

/* stop polling a specific slow-sync client
 *
 *   precondition: caller holds the graph lock. */
static inline void
jack_sync_poll_deactivate (jack_client_internal_t *client);

/* stop polling all the slow-sync clients
 *
 *   precondition: caller holds the graph lock. */
static void
jack_sync_poll_stop ();

/* start polling all the slow-sync clients
 *
 *   precondition: caller holds the graph lock. */
static void
jack_sync_poll_start ();

/* check for sync timeout */
static inline int
jack_sync_timeout ();


/**************** subroutines used by engine.c ****************/

/* driver callback */
int
jack_set_sample_rate ( jack_nframes_t nframes);

/* on ResetTimeBaseClient request */
int
jack_timebase_reset ( jack_client_id_t client_id);

/* on SetTimeBaseClient request */
int
jack_timebase_set (jack_client_id_t client_id, int conditional);

/* for client activation
 *
 *   precondition: caller holds the graph lock. */
void
jack_transport_activate (jack_client_internal_t *client);

/* for engine initialization */
void
jack_transport_init ();

/* when any client exits the graph (either dead or not active)
 *
 * precondition: caller holds the graph lock */
void
jack_transport_client_exit (jack_client_internal_t *client);

/* when a new client is being created */
void	
jack_transport_client_new (jack_client_internal_t *client);

/* on ResetSyncClient request */
int
jack_transport_client_reset_sync (jack_client_id_t client_id);

/* on SetSyncClient request */
int
jack_transport_client_set_sync (jack_client_id_t client_id);

/* at process cycle end, set transport parameters for the next cycle
 *
 * precondition: caller holds the graph lock.
 */
void
jack_transport_cycle_end ();

/* driver callback at start of cycle */
static void 
jack_transport_cycle_start (jack_engine_t *engine, jack_time_t time) ;

/* on SetSyncTimeout request */
int	
jack_transport_set_sync_timeout (jack_time_t usecs);
};


#define jack_rdlock_graph(e) { DEBUG ("acquiring graph read lock"); if (pthread_rwlock_rdlock (&e->_client_lock)) abort(); }
#define jack_lock_graph(e) { DEBUG ("acquiring graph write lock"); if (pthread_rwlock_wrlock (&e->_client_lock)) abort(); }
#define jack_try_rdlock_graph(e) pthread_rwlock_tryrdlock (&e->client_lock)
#define jack_unlock_graph(e) { DEBUG ("release graph lock"); if (pthread_rwlock_unlock (&e->_client_lock)) abort(); }

#define jack_trylock_problems(e) pthread_mutex_trylock (&e->_problem_lock)
#define jack_lock_problems(e) { DEBUG ("acquiring problem lock"); if (pthread_mutex_lock (&e->_problem_lock)) abort(); }
#define jack_unlock_problems(e) { DEBUG ("release problem lock"); if (pthread_mutex_unlock (&e->_problem_lock)) abort(); }

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


extern jack_timer_type_t clock_source; 
#endif /* __jack_engine_h__ */
