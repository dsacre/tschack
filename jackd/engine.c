/* -*- mode: c; c-file-style: "bsd"; -*- */
/*
    Copyright (C) 2001-2003 Paul Davis
    Copyright (C) 2004 Jack O'Quin
    
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

#include <config.h>

#include <math.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

#include <jack/internal.h>
#include <jack/engine.h>
#include <jack/messagebuffer.h>
#include <jack/driver.h>
#include <jack/shm.h>
#include <jack/thread.h>
#include <sysdeps/poll.h>
#include <sysdeps/ipc.h>

#ifdef USE_MLOCK
#include <sys/mman.h>
#endif /* USE_MLOCK */

#ifdef USE_CAPABILITIES
/* capgetp and capsetp are linux only extensions, not posix */
#undef _POSIX_SOURCE
#include <sys/capability.h>
#endif

#include "clientengine.h"
#include "transengine.h"

#include "libjack/local.h"

// XXX:
#define PRIu32 "u"
#define PRIu64 "lu"

#include <exception>

inline int 
jack_engine_t::jack_rolling_interval (jack_time_t period_usecs)
{
	return floor ((JACK_ENGINE_ROLLING_INTERVAL * 1000.0f) / period_usecs);
}

void
jack_engine_t::jack_engine_reset_rolling_usecs ()
{
	memset (_rolling_client_usecs, 0,
		sizeof (_rolling_client_usecs));
	_rolling_client_usecs_index = 0;
	_rolling_client_usecs_cnt = 0;

	if (_driver) {
		_rolling_interval =
			jack_rolling_interval (_driver->period_usecs);
	} else {
		_rolling_interval = JACK_ENGINE_ROLLING_INTERVAL;
	}

	_spare_usecs = 0;
}

inline jack_port_type_info_t *
jack_engine_t::jack_port_type_info ( jack_port_internal_t *port)
{
	/* Returns a pointer to the port type information in the
	   engine's shared control structure. 
	*/
	return &_control->port_types[port->shared->ptype_id];
}

inline jack_port_buffer_list_t *
jack_engine_t::jack_port_buffer_list ( jack_port_internal_t *port)
{
	/* Points to the engine's private port buffer list struct. */
	return &_port_buffers[port->shared->ptype_id];
}

int
jack_engine_t::make_directory (const char *path)
{
	struct stat statbuf;

	if (stat (path, &statbuf)) {

		if (errno == ENOENT) {
			int mode;

			if (getenv ("JACK_PROMISCUOUS_SERVER")) {
				mode = 0777;
			} else {
				mode = 0700;
			}

			if (mkdir (path, mode) < 0){
				jack_error ("cannot create %s directory (%s)\n",
					    path, strerror (errno));
				return -1;
			}
		} else {
			jack_error ("cannot stat() %s\n", path);
			return -1;
		}

	} else {

		if (!S_ISDIR (statbuf.st_mode)) {
			jack_error ("%s already exists, but is not"
				    " a directory!\n", path);
			return -1;
		}
	}

	return 0;
}

int
jack_engine_t::make_socket_subdirectories (const char *server_name)
{
	struct stat statbuf;
        char server_dir[PATH_MAX+1] = "";

	/* check tmpdir directory */
	if (stat (jack_tmpdir, &statbuf)) {
		jack_error ("cannot stat() %s (%s)\n",
			    jack_tmpdir, strerror (errno));
		return -1;
	} else {
		if (!S_ISDIR(statbuf.st_mode)) {
			jack_error ("%s exists, but is not a directory!\n",
				    jack_tmpdir);
			return -1;
		}
	}

	/* create user subdirectory */
	if (make_directory (jack_user_dir ()) < 0) {
		return -1;
	}

	/* create server_name subdirectory */
	if (make_directory (jack_server_dir (server_name, server_dir)) < 0) {
		return -1;
	}

	return 0;
}

int
jack_engine_t::make_sockets (const char *server_name, int fd[2])
{
	struct sockaddr_un addr;
	int i;
        char server_dir[PATH_MAX+1] = "";

	if (make_socket_subdirectories (server_name) < 0) {
		return -1;
	}

	/* First, the master server socket */

	if ((fd[0] = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		jack_error ("cannot create server socket (%s)",
			    strerror (errno));
		return -1;
	}

	addr.sun_family = AF_UNIX;
	for (i = 0; i < 999; i++) {
		snprintf (addr.sun_path, sizeof (addr.sun_path) - 1,
			  "%s/jack_%d", jack_server_dir (server_name, server_dir), i);
		if (access (addr.sun_path, F_OK) != 0) {
			break;
		}
	}

	if (i == 999) {
		jack_error ("all possible server socket names in use!!!");
		close (fd[0]);
		return -1;
	}

	if (bind (fd[0], (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		jack_error ("cannot bind server to socket (%s)",
			    strerror (errno));
		close (fd[0]);
		return -1;
	}

	if (listen (fd[0], 1) < 0) {
		jack_error ("cannot enable listen on server socket (%s)",
			    strerror (errno));
		close (fd[0]);
		return -1;
	}

	/* Now the client/server event ack server socket */

	if ((fd[1] = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		jack_error ("cannot create event ACK socket (%s)",
			    strerror (errno));
		close (fd[0]);
		return -1;
	}

	addr.sun_family = AF_UNIX;
	for (i = 0; i < 999; i++) {
		snprintf (addr.sun_path, sizeof (addr.sun_path) - 1,
			  "%s/jack_ack_%d", jack_server_dir (server_name, server_dir), i);
		if (access (addr.sun_path, F_OK) != 0) {
			break;
		}
	}

	if (i == 999) {
		jack_error ("all possible server ACK socket names in use!!!");
		close (fd[0]);
		close (fd[1]);
		return -1;
	}

	if (bind (fd[1], (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		jack_error ("cannot bind server to socket (%s)",
			    strerror (errno));
		close (fd[0]);
		close (fd[1]);
		return -1;
	}

	if (listen (fd[1], 1) < 0) {
		jack_error ("cannot enable listen on server socket (%s)",
			    strerror (errno));
		close (fd[0]);
		close (fd[1]);
		return -1;
	}

	return 0;
}

void
jack_engine_t::jack_engine_place_port_buffers ( 
				jack_port_type_id_t ptid,
				jack_shmsize_t one_buffer,
				jack_shmsize_t size,
				unsigned long nports,
				jack_nframes_t nframes)
{
	jack_shmsize_t offset;		/* shared memory offset */
	jack_port_buffer_info_t *bi;
	jack_port_buffer_list_t* pti = &_port_buffers[ptid];
	jack_port_functions_t *pfuncs = jack_get_port_functions(ptid);

	pthread_mutex_lock (&pti->lock);
	offset = 0;
	
	if (pti->info) {

		/* Buffer info array already allocated for this port
		 * type.  This must be a resize operation, so
		 * recompute the buffer offsets, but leave the free
		 * list alone.
		 */
		int i;

		bi = pti->info;
		while (offset < size) {
			bi->offset = offset;
			offset += one_buffer;
			++bi;
		}

		/* update any existing output port offsets */
		for (i = 0; i < _port_max; i++) {
			jack_port_shared_t *port = &_control->ports[i];
			if (port->in_use &&
			    (port->flags & JackPortIsOutput) &&
			    port->ptype_id == ptid) {
				bi = _internal_ports[i].buffer_info;
				if (bi) {
					port->offset = bi->offset;
				}
			}
		}

	} else {
		jack_port_type_info_t* port_type = &_control->port_types[ptid];

		/* Allocate an array of buffer info structures for all
		 * the buffers in the segment.  Chain them to the free
		 * list in memory address order, offset zero must come
		 * first.
		 */
		bi = pti->info = (jack_port_buffer_info_t *)
			malloc (nports * sizeof (jack_port_buffer_info_t));

		while (offset < size) {
			bi->offset = offset;
			pti->freelist = jack_slist_append (pti->freelist, bi);
			offset += one_buffer;
			++bi;
		}

		/* Allocate the first buffer of the port segment
		 * for an empy buffer area.
		 * NOTE: audio buffer is zeroed in its buffer_init function.
		 */
		bi = (jack_port_buffer_info_t *) pti->freelist->data;
		pti->freelist = jack_slist_remove_link (pti->freelist,
							pti->freelist);
		port_type->zero_buffer_offset = bi->offset;
		if (ptid == JACK_AUDIO_PORT_TYPE)
			_silent_buffer = bi;
	}
	/* initialize buffers */
	{
		int i;
		jack_shm_info_t *shm_info = &_port_segment[ptid];
		char* shm_segment = (char *) jack_shm_addr(shm_info);

		bi = pti->info;
		for (i=0; i<nports; ++i, ++bi)
			pfuncs->buffer_init(shm_segment + bi->offset, one_buffer, nframes);
	}

	pthread_mutex_unlock (&pti->lock);
}


int
jack_engine_t::jack_resize_port_segment (
			  jack_port_type_id_t ptid,
			  unsigned long nports)
{
	jack_event_t event;
	jack_shmsize_t one_buffer;	/* size of one buffer */
	jack_shmsize_t size;		/* segment size */
	jack_port_type_info_t* port_type = &_control->port_types[ptid];
	jack_shm_info_t* shm_info = &_port_segment[ptid];

	one_buffer = jack_port_type_buffer_size (port_type, _control->buffer_size);
	VERBOSE (this, "resizing port buffer segment for type %d, one buffer = %u bytes", ptid, one_buffer);

	size = nports * one_buffer;

	if (shm_info->attached_at == 0) {

		if (jack_shmalloc (size, shm_info)) {
			jack_error ("cannot create new port segment of %d"
				    " bytes (%s)", 
				    size,
				    strerror (errno));
			return -1;
		}
		
		if (jack_attach_shm (shm_info)) {
			jack_error ("cannot attach to new port segment "
				    "(%s)", strerror (errno));
			return -1;
		}

		_control->port_types[ptid].shm_registry_index =
			shm_info->index;

	} else {

		/* resize existing buffer segment */
		if (jack_resize_shm (shm_info, size)) {
			jack_error ("cannot resize port segment to %d bytes,"
				    " (%s)", size,
				    strerror (errno));
			return -1;
		}
	}

	jack_engine_place_port_buffers (ptid, one_buffer, size, nports, _control->buffer_size);

#ifdef USE_MLOCK
	if (_control->real_time) {

	/* Although we've called mlockall(CURRENT|FUTURE), the
		 * Linux VM manager still allows newly allocated pages
		 * to fault on first reference.  This mlock() ensures
		 * that any new pages are present before restarting
		 * the process cycle.  Since memory locks do not
		 * stack, they can still be unlocked with a single
		 * munlockall().
		 */

		int rc = mlock (jack_shm_addr (shm_info), size);
		if (rc < 0) {
			jack_error("JACK: unable to mlock() port buffers: "
				   "%s", strerror(errno));
		}
	}
#endif /* USE_MLOCK */

	/* Tell everybody about this segment. */
	event.type = AttachPortSegment;
	event.y.ptid = ptid;
	jack_deliver_event_to_all (&event);

	/* XXX need to clean up in the evnt of failures */

	return 0;
}

/* The driver invokes this callback both initially and whenever its
 * buffer size changes. 
 */
int
jack_engine_t::jack_driver_buffer_size ( jack_nframes_t nframes)
{
	int i;
	jack_event_t event;
	JSList *node;

	VERBOSE (this, "new buffer size %" PRIu32, nframes);

	_control->buffer_size = nframes;
	if (_driver)
		_rolling_interval =
			jack_rolling_interval (_driver->period_usecs);

	for (i = 0; i < _control->n_port_types; ++i) {
		if (jack_resize_port_segment (i, _control->port_max)) {
			return -1;
		}
	}

	/* update shared client copy of nframes */
	jack_lock_graph (this);
	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t *client = (jack_client_internal_t *) node->data;
		client->control->nframes = nframes;
	}
	jack_unlock_graph (this);

	event.type = BufferSizeChange;
	jack_deliver_event_to_all (&event);

	return 0;
}

int
jack_engine_t::jack_driver_buffer_size_aux ( jack_engine_t *engine, jack_nframes_t nframes)
{
	return engine->jack_driver_buffer_size (nframes);
}

/* handle client SetBufferSize request */
int
jack_engine_t::jack_set_buffer_size_request ( jack_nframes_t nframes)
{
	/* precondition: caller holds the request_lock */
	int rc;
	jack_driver_t* driver = _driver;

	if (driver == NULL)
		return ENXIO;		/* no such device */

	if (!jack_power_of_two(nframes)) {
  		jack_error("buffer size %" PRIu32 " not a power of 2",
			   nframes);
		return EINVAL;
	}

	rc = driver->bufsize(driver, nframes);
	if (rc != 0)
		jack_error("driver does not support %" PRIu32
			   "-frame buffers", nframes);

	return rc;
}


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
jack_engine_t::linux_poll_bug_encountered ( jack_time_t then, jack_time_t *required)
{
	if (_control->clock_source != JACK_TIMER_SYSTEM_CLOCK || system_clock_monotonic) {
		jack_time_t now = jack_get_microseconds ();

		if ((now - then) < *required) {
			
			/*
			   So, adjust poll timeout to account for time already spent waiting.
			*/
			
			VERBOSE (this, "FALSE WAKEUP (%lldusecs vs. %lld usec)", (now - then), *required);
			*required -= (now - then);

			/* allow 0.25msec slop */
			return 1;
		}
	}
	return 0;
}
#endif


int 
jack_engine_t::jack_engine_get_execution_token ()
{
	if( __exchange_and_add( &(_control->execution_tokens), -1 ) < 1 ) {
	  __exchange_and_add( &(_control->execution_tokens), 1 ); 
	  return 0;
	}
	return 1;
}

int 
jack_engine_t::jack_engine_trigger_client ( jack_client_internal_t *client )
{
	char c = 0;
	//struct pollfd pfd[1];
	jack_client_control_t *ctl;
	jack_per_client_ctl_t *pcl = & (_control->per_client[client->control->id]);
	//int curr_chain = _control->current_process_chain; 

	ctl = client->control;

	if( jack_engine_get_execution_token () ) 
	{
		/* a race exists if we do this after the write(2) */
	  if (__exchange_and_add( &(pcl->signal_token), -1 ) == 1 )
	  {
	        DEBUG( "signaling... " );
		pcl->state = Signaled; 

		pcl->triggered_at = jack_get_microseconds();
		pcl->signalled_at = jack_get_microseconds();

		if (write (client->subgraph_start_fd, &c, sizeof (c)) != sizeof (c)) {
			jack_error ("cannot initiate graph processing (%s)",
					strerror (errno));
			_process_errors++;
			// we already hold the problem lock.
			_problems++;
			return -1; /* will stop the loop */
		} 
	  } else {
	    __atomic_add( &(_control->execution_tokens), 1 ); 
	  }
	} else {
	        DEBUG( "only setting the trigger." );
		pcl->state = Triggered; 
		pcl->triggered_at = jack_get_microseconds();
	}

	return 0;
}

int
jack_engine_t::jack_engine_cleanup_graph_wait ( int min_tokens)
{
	int rb;
	char c[16];

	DEBUG ("reading byte from subgraph_wait_fd==%d chain=%d",
			_graph_wait_fd);
	rb = read (_graph_wait_fd, c, sizeof(c));
	if (min_tokens && (rb < min_tokens)) {
		jack_error ("pp: cannot clean up byte from graph wait "
				"fd (%s)", strerror (errno));
		return -1;	/* will stop the loop */
	}
	return 0;
}

int
jack_engine_t::jack_engine_wait_graph ()
{
	int status = 0;
	struct pollfd pfd[1];
	int poll_timeout;
	jack_time_t poll_timeout_usecs;
	jack_time_t now, then;
	int pollret;
	//int curr_chain = _control->current_process_chain;

	then = jack_get_microseconds ();

	if (_freewheeling) {
		poll_timeout_usecs = 250000; /* 0.25 seconds */
	} else {
		poll_timeout_usecs = (_client_timeout_msecs > 0 ?
				_client_timeout_msecs * 1000 :
				_driver->period_usecs);
	}

     again:
	poll_timeout = 1 + poll_timeout_usecs / 1000;
	pfd[0].fd = _graph_wait_fd;
	pfd[0].events = POLLERR|POLLIN|POLLHUP|POLLNVAL;

	DEBUG ("waiting on fd==%d for process() subgraph to finish (timeout = %d, period_usecs = %d)",
	       _graph_wait_fd, poll_timeout, _driver->period_usecs);

	if ((pollret = poll (pfd, 1, poll_timeout)) < 0) {
		jack_error ("poll on subgraph processing failed (%s)",
			    strerror (errno));
		status = -1; 
	}

	DEBUG ("\n\n\n\n\n back from subgraph poll, revents = 0x%x\n\n\n", pfd[0].revents);

	if (pfd[0].revents & ~POLLIN) {
		jack_error ("subgraph starting at lost client");
		status = -2; 
	}

	if (pfd[0].revents & POLLIN) {

		status = 0;

	} else if (status == 0) {

		/* no events, no errors, we woke up because poll()
		   decided that time was up ...
		*/

		if (_freewheeling) {
			if (jack_check_client_status ()) {
				return -1;
			} else {
				/* all clients are fine - we're just not done yet. since
				   we're freewheeling, that is fine.
				*/
				goto again;
			}
		}

#ifdef __linux		
		if (linux_poll_bug_encountered (then, &poll_timeout_usecs)) {
			goto again;
		}

		if (poll_timeout_usecs < 200) {
			VERBOSE (this, "FALSE WAKEUP skipped, remaining = %lld usec", poll_timeout_usecs);
		} else {
#endif
			
		jack_error ("graph timed out "
			    "(graph_wait_fd=%d, status = %d, pollret = %d revents = 0x%x)", 
			    _graph_wait_fd, status, 
			    pollret, pfd[0].revents);
		status = 1;
#ifdef __linux
		}
#endif
	}

	now = jack_get_microseconds ();

	if (status != 0) {
		VERBOSE (this, "at %" PRIu64
			 " waiting on %d for %" PRIu64
			 " usecs, status = %d",
			 now,
			 _graph_wait_fd,
			 now - then,
			 status );

		if (jack_check_clients (1)) {

			_process_errors++;
			return -1;		/* will stop the loop */
		}
	} else {
		_timeout_count = 0;
	}
	if (jack_engine_cleanup_graph_wait (1)) {
		return -1;

	}

	return 0;
}
int
jack_engine_t::jack_engine_process ( jack_nframes_t nframes)
{
	/* precondition: caller has current chain lock */
	jack_client_internal_t *client;
	JSList *node, *pnode;
	int curr_chain = _control->current_process_chain; 
	int i;

	_process_errors = 0;
	_watchdog_check = 1;

	if( _server_wakeup_list[curr_chain] ) 
		jack_engine_cleanup_graph_wait (0);

	for (i=0; i<JACK_MAX_CLIENTS; i++ ) {
		jack_per_client_ctl_t *pcl = & (_control->per_client[i]);
		pcl->state = NotTriggered;
		pcl->signal_token = 1;
		pcl->signalled_at = 0;
		pcl->triggered_at = 0;
	}

	for (node = _process_graph_list[curr_chain]; node; node = jack_slist_next (node)) {
		client = (jack_client_internal_t *) node->data;
		jack_client_control_t *ctl = client->control;
		jack_per_client_ctl_t *pcl = & (_control->per_client[ctl->id]);

		ctl->nframes = nframes;
		ctl->timed_out = 0;
		ctl->awake_at = 0;
		ctl->finished_at = 0;

		for( pnode = client->ports_rt[curr_chain]; pnode; pnode=jack_slist_next(pnode) ) {
		  jack_port_internal_t *port = (jack_port_internal_t *) pnode->data;
		  port->shared->activation_count = _port_activation_counts_init[curr_chain][port->shared->id];
		}

		pcl->activation_count = 
		  _client_activation_counts_init[curr_chain][ctl->id];
	}

	_control->execution_tokens = _jobs;

	for (node = _server_wakeup_list[curr_chain]; node; node=jack_slist_next(node) ) {

		client = (jack_client_internal_t *) node->data;
		
		DEBUG ("triggering client %s for processing",
		       client->control->name);

		jack_engine_trigger_client( client );
	}

	if (_process_errors > 0)
	  return -1;

	if( _server_wakeup_list[curr_chain] ) 
	  return jack_engine_wait_graph( );
	
	return 0;
}

void 
jack_engine_t::jack_calc_cpu_load()
{
	jack_time_t cycle_end = jack_get_microseconds ();
	
	/* store the execution time for later averaging */

	_rolling_client_usecs[_rolling_client_usecs_index++] = 
		cycle_end - _control->current_time.usecs;

	//jack_info ("cycle_end - _control->current_time.usecs %ld",
	//	(long) (cycle_end - _control->current_time.usecs));

	if (_rolling_client_usecs_index >= JACK_ENGINE_ROLLING_COUNT) {
		_rolling_client_usecs_index = 0;
	}

	/* every so often, recompute the current maximum use over the
	   last JACK_ENGINE_ROLLING_COUNT client iterations.
	*/

	if (++_rolling_client_usecs_cnt
	    % _rolling_interval == 0) {
		float max_usecs = 0.0f;
		int i;

		for (i = 0; i < JACK_ENGINE_ROLLING_COUNT; i++) {
			if (_rolling_client_usecs[i] > max_usecs) {
				max_usecs = _rolling_client_usecs[i];
			}
		}

		if (max_usecs > _max_usecs) {
			_max_usecs = max_usecs;
		}

		if (max_usecs < _driver->period_usecs) {
			_spare_usecs =
				_driver->period_usecs - max_usecs;
		} else {
			_spare_usecs = 0;
		}

		_control->cpu_load =
			(1.0f - (_spare_usecs /
				 _driver->period_usecs)) * 50.0f
			+ (_control->cpu_load * 0.5f);

		VERBOSE (this, "load = %.4f max usecs: %.3f, "
			 "spare = %.3f", _control->cpu_load,
			 max_usecs, _spare_usecs);
	}

}

void
jack_engine_t::jack_engine_post_process ()
{
	/* precondition: caller holds the graph lock. */

	jack_transport_cycle_end ();
	jack_calc_cpu_load ();
	jack_check_clients (0);
}

#ifdef JACK_USE_MACH_THREADS

int
jack_engine_t::jack_start_watchdog ()
{
	/* Stephane Letz : letz@grame.fr Watch dog thread is
	 * not needed on MacOSX since CoreAudio drivers
	 * already contains a similar mechanism.
	 */
	return 0;
}

void
jack_engine_t::jack_stop_watchdog ()
{
	/* Stephane Letz : letz@grame.fr Watch dog thread is
	 * not needed on MacOSX since CoreAudio drivers
	 * already contains a similar mechanism.
	 */
	return;
}

#else

void *
jack_engine_t::jack_watchdog_thread_aux (void *arg)
{
	jack_engine_t *engine = (jack_engine_t *) arg;
	return engine->jack_watchdog_thread();
}

void *
jack_engine_t::jack_watchdog_thread ()
{
	struct timespec timo;

	timo.tv_sec = JACKD_WATCHDOG_TIMEOUT / 1000;
	timo.tv_nsec = (JACKD_WATCHDOG_TIMEOUT - (timo.tv_sec * 1000)) * 1000;
	_watchdog_check = 0;

	while (1) {
        nanosleep (&timo, NULL);
		if (!_freewheeling && _watchdog_check == 0) {

			jack_error ("jackd watchdog: timeout - killing jackd");

			/* Kill the current client (guilt by association). */
			if (_current_client) {
					kill (_current_client->
					      control->pid, SIGKILL);
			}

			/* kill our process group, try to get a dump */
			kill (-getpgrp(), SIGABRT);
			/*NOTREACHED*/
			exit (1);
		}
		_watchdog_check = 0;
	}
}

int
jack_engine_t::jack_start_watchdog ()
{
	int watchdog_priority = _rtpriority + 10;
#ifndef __OpenBSD__
	int max_priority = sched_get_priority_max (SCHED_FIFO);
#else
	int max_priority = -1;
#endif

	if ((max_priority != -1) &&
	    (max_priority < watchdog_priority))
		watchdog_priority = max_priority;
	
	if (jack_client_create_thread (NULL, &_watchdog_thread, watchdog_priority,
				       TRUE, jack_watchdog_thread_aux, this)) {
		jack_error ("cannot start watchdog thread");
		return -1;
	}

	return 0;
}

void
jack_engine_t::jack_stop_watchdog ()
{
	/* Cancel the watchdog thread and wait for it to terminate.
	 *
	 * The watchdog thread is not used on MacOSX since CoreAudio
	 * drivers already contain a similar mechanism.
	 */	
	if (_control->real_time && _watchdog_thread) {
		VERBOSE (this, "stopping watchdog thread");
		pthread_cancel (_watchdog_thread);
		pthread_join (_watchdog_thread, NULL);
	}

	return;
}
#endif /* !JACK_USE_MACH_THREADS */


jack_driver_info_t *
jack_engine_t::jack_load_driver ( jack_driver_desc_t * driver_desc)
{
	const char *errstr;
	jack_driver_info_t *info;

	info = (jack_driver_info_t *) calloc (1, sizeof (*info));

	info->handle = dlopen (driver_desc->file, RTLD_NOW|RTLD_GLOBAL);
	
	if (info->handle == NULL) {
		if ((errstr = dlerror ()) != 0) {
			jack_error ("can't load \"%s\": %s", driver_desc->file,
				    errstr);
		} else {
			jack_error ("bizarre error loading driver shared "
				    "object %s", driver_desc->file);
		}
		goto fail;
	}

	info->initialize = (jack_driver_t* (*)(jack_client_t*, const JSList*)) dlsym (info->handle, "driver_initialize");

	if ((errstr = dlerror ()) != 0) {
		jack_error ("no initialize function in shared object %s\n",
			    driver_desc->file);
		goto fail;
	}

	info->finish = dlsym (info->handle, "driver_finish");

	if ((errstr = dlerror ()) != 0) {
		jack_error ("no finish function in in shared driver object %s",
			    driver_desc->file);
		goto fail;
	}

	info->client_name = (char *) dlsym (info->handle, "driver_client_name");

	if ((errstr = dlerror ()) != 0) {
		jack_error ("no client name in in shared driver object %s",
			    driver_desc->file);
		goto fail;
	}

	return info;

  fail:
	if (info->handle) {
		dlclose (info->handle);
	}
	free (info);
	return NULL;
	
}

void
jack_engine_t::jack_driver_unload (jack_driver_t *driver)
{
	void* handle = driver->handle;
	driver->finish (driver);
	dlclose (handle);
}

int
jack_engine_t::jack_engine_load_driver (
			 jack_driver_desc_t * driver_desc,
			 JSList * driver_params)
{
	jack_client_internal_t *client;
	jack_driver_t *driver;
	jack_driver_info_t *info;

	if ((info = jack_load_driver (driver_desc)) == NULL) {
		return -1;
	}

	if ((client = jack_create_driver_client (info->client_name)
		    ) == NULL) {
		return -1;
	}

	if ((driver = info->initialize (client->private_client,
					driver_params)) == NULL) {
		free (info);
		return -1;
	}

	driver->handle = info->handle;
	driver->finish = (void (*)(jack_driver_t*)) info->finish;
	driver->internal_client = client;
	free (info);

	if (jack_use_driver (driver) < 0) {
		jack_client_delete (client);
		return -1;
	}

	_driver_desc   = driver_desc;
	_driver_params = driver_params;

	if (_control->real_time) {
		if (jack_start_watchdog ()) {
			return -1;
		}
		_watchdog_check = 1;
	}
	return 0;
}

#ifdef USE_CAPABILITIES

int 
jack_engine_t::check_capabilities ()
{
	cap_t caps = cap_init();
	cap_flag_value_t cap;
	pid_t pid;
	int have_all_caps = 1;

	if (caps == NULL) {
		VERBOSE (this, "check: could not allocate capability"
			 " working storage");
		return 0;
	}
	pid = getpid ();
	cap_clear (caps);
	if (capgetp (pid, caps)) {
		VERBOSE (this, "check: could not get capabilities "
			 "for process %d", pid);
		return 0;
	}
	/* check that we are able to give capabilites to other processes */
	cap_get_flag(caps, CAP_SETPCAP, CAP_EFFECTIVE, &cap);
	if (cap == CAP_CLEAR) {
		have_all_caps = 0;
		goto done;
	}
	/* check that we have the capabilities we want to transfer */
	cap_get_flag(caps, CAP_SYS_NICE, CAP_EFFECTIVE, &cap);
	if (cap == CAP_CLEAR) {
		have_all_caps = 0;
		goto done;
	}
	cap_get_flag(caps, CAP_SYS_RESOURCE, CAP_EFFECTIVE, &cap);
	if (cap == CAP_CLEAR) {
		have_all_caps = 0;
		goto done;
	}
	cap_get_flag(caps, CAP_IPC_LOCK, CAP_EFFECTIVE, &cap);
	if (cap == CAP_CLEAR) {
		have_all_caps = 0;
		goto done;
	}
  done:
	cap_free (caps);
	return have_all_caps;
}


int 
jack_engine_t::give_capabilities ( pid_t pid)
{
	cap_t caps = cap_init();
	const unsigned caps_size = 3;
	cap_value_t cap_list[] = {CAP_SYS_NICE, CAP_SYS_RESOURCE, CAP_IPC_LOCK};

	if (caps == NULL) {
		VERBOSE (this, "give: could not allocate capability"
			 " working storage");
		return -1;
	}
	cap_clear(caps);
	if (capgetp (pid, caps)) {
		VERBOSE (this, "give: could not get current "
			 "capabilities for process %d", pid);
		cap_clear(caps);
	}
	cap_set_flag(caps, CAP_EFFECTIVE, caps_size, cap_list , CAP_SET);
	cap_set_flag(caps, CAP_INHERITABLE, caps_size, cap_list , CAP_SET);
	cap_set_flag(caps, CAP_PERMITTED, caps_size, cap_list , CAP_SET);
	if (capsetp (pid, caps)) {
		cap_free (caps);
		return -1;
	}
	cap_free (caps);
	return 0;
}

int
jack_engine_t::jack_set_client_capabilities ( pid_t cap_pid)
{
	int ret = -1;

	/* before sending this request the client has
	   already checked that the engine has
	   realtime capabilities, that it is running
	   realtime and that the pid is defined
	*/

	if ((ret = give_capabilities (cap_pid)) != 0) {
		jack_error ("could not give capabilities to "
			    "process %d",
			    cap_pid);
	} else {
		VERBOSE (this, "gave capabilities to"
			 " process %d",
			 cap_pid);
	}

	return ret;
}	

#endif /* USE_CAPABILITIES */

/* perform internal or external client request
 *
 * reply_fd is NULL for internal requests
 */
void
jack_engine_t::do_request ( jack_request_t *req, int *reply_fd)
{
	/* The request_lock serializes internal requests (from any
	 * thread in the server) with external requests (always from "the"
	 * server thread). 
	 */
	pthread_mutex_lock (&_request_lock);

	DEBUG ("got a request of type %d", req->type);

	switch (req->type) {
	case RegisterPort:
		req->status = jack_port_do_register (req, reply_fd ? FALSE : TRUE);
		break;

	case UnRegisterPort:
		req->status = jack_port_do_unregister (req);
		break;

	case ConnectPorts:
		req->status = jack_port_do_connect
			(req->x.connect.source_port,
			 req->x.connect.destination_port);
		break;

	case DisconnectPort:
		req->status = jack_port_do_disconnect_all
			(req->x.port_info.port_id);
		break;

	case DisconnectPorts:
		req->status = jack_port_do_disconnect
			(req->x.connect.source_port,
			 req->x.connect.destination_port);
		break;

	case ActivateClient:
		req->status = jack_client_activate (req->x.client_id);
		break;

	case DeactivateClient:
		req->status = jack_client_deactivate (req->x.client_id);
		break;

	case SetTimeBaseClient:
		req->status = jack_timebase_set (
						 req->x.timebase.client_id,
						 req->x.timebase.conditional);
		break;

	case ResetTimeBaseClient:
		req->status = jack_timebase_reset (req->x.client_id);
		break;

	case SetSyncClient:
		req->status =
			jack_transport_client_set_sync (
							req->x.client_id);
		break;

	case ResetSyncClient:
		req->status =
			jack_transport_client_reset_sync (
							  req->x.client_id);
		break;

	case SetSyncTimeout:
		req->status = jack_transport_set_sync_timeout (
							       req->x.timeout);
		break;

#ifdef USE_CAPABILITIES
	case SetClientCapabilities:
		req->status = jack_set_client_capabilities (
							    req->x.cap_pid);
		break;
#endif /* USE_CAPABILITIES */
		
	case GetPortConnections:
	case GetPortNConnections:
		//JOQ bug: reply_fd may be NULL if internal request
		if ((req->status =
		     jack_do_get_port_connections (req, *reply_fd))
		    == 0) {
			/* we have already replied, don't do it again */
			*reply_fd = -1;
		}
		break;

	case FreeWheel:
		req->status = jack_start_freewheeling (req->x.client_id);
		break;

	case StopFreeWheel:
		req->status = jack_stop_freewheeling (0);
		break;

	case SetBufferSize:
		req->status = jack_set_buffer_size_request (
							   req->x.nframes);
		break;

	case IntClientHandle:
		jack_intclient_handle_request (req);
		break;

	case IntClientLoad:
		jack_intclient_load_request (req);
		break;

	case IntClientName:
		jack_intclient_name_request (req);
		break;

	case IntClientUnload:
		jack_intclient_unload_request (req);
		break;

	case RecomputeTotalLatencies:
		jack_lock_graph (this);
		jack_compute_all_port_total_latencies ();
		jack_unlock_graph (this);
		req->status = 0;
		break;

	case RecomputeTotalLatency:
		jack_lock_graph (this);
		jack_compute_port_total_latency (&_control->ports[req->x.port_info.port_id]);
		jack_unlock_graph (this);
		req->status = 0;
		break;

	case GetClientByUUID:
		jack_rdlock_graph (this);
		jack_do_get_client_by_uuid (req);
		jack_unlock_graph (this);
		break;
	case ReserveName:
		jack_rdlock_graph (this);
		jack_do_reserve_name (req);
		jack_unlock_graph (this);
		break;
	case SessionReply:
		jack_rdlock_graph (this);
		jack_do_session_reply (req);
		jack_unlock_graph (this);
		break;
	case SessionNotify:
		jack_rdlock_graph (this);
		if ((req->status =
	  	    jack_do_session_notify (req, *reply_fd))
		    >= 0) {
			/* we have already replied, don't do it again */
			*reply_fd = -1;
		}
		jack_unlock_graph (this);
		break;
	default:
		/* some requests are handled entirely on the client
		 * side, by adjusting the shared memory area(s) */
		break;
	}

	pthread_mutex_unlock (&_request_lock);

	DEBUG ("status of request: %d", req->status);
}

int
jack_engine_t::internal_client_request (void* ptr, jack_request_t *request)
{
	jack_engine_t *engine = (jack_engine_t *) ptr;

	engine->do_request (request, NULL);
	return request->status;
}

int
jack_engine_t::handle_external_client_request ( int fd)
{
	/* CALLER holds read lock on graph */

	jack_request_t req;
	jack_client_internal_t *client = 0;
	int reply_fd;
	JSList *node;
	ssize_t r;

	for (node = _clients; node; node = jack_slist_next (node)) {
		if (((jack_client_internal_t *) node->data)->request_fd == fd) {
			client = (jack_client_internal_t *) node->data;
			break;
		}
	}

	if (client == NULL) {
		jack_error ("client input on unknown fd %d!", fd);
		return -1;
	}

	if ((r = read (client->request_fd, &req, sizeof (req)))
	    < (ssize_t) sizeof (req)) {
		if (r == 0) {
#ifdef JACK_USE_MACH_THREADS
			/* poll is implemented using
			   select (see the macosx/fakepoll
			   code). When the socket is closed
			   select does not return any error,
			   POLLIN is true and the next read
			   will return 0 bytes. This
			   behaviour is diffrent from the
			   Linux poll behaviour. Thus we use
			   this condition as a socket error
			   and remove the client.
			*/
			jack_mark_client_socket_error (fd);
#endif /* JACK_USE_MACH_THREADS */
			return 1;
		} else {
			jack_error ("cannot read request from client (%d/%d/%s)",
				    r, sizeof(req), strerror (errno));
			// XXX: shouldnt we mark this client as error now ?

			return -1;
		}
	}

	reply_fd = client->request_fd;
	
	jack_unlock_graph (this);
	do_request (&req, &reply_fd);
	jack_lock_graph (this);

	if (reply_fd >= 0) {
		DEBUG ("replying to client");
		if (write (reply_fd, &req, sizeof (req))
		    < (ssize_t) sizeof (req)) {
			jack_error ("cannot write request result to client");
			return -1;
		}
	} else {
		DEBUG ("*not* replying to client");
        }

	return 0;
}

int
jack_engine_t::handle_client_ack_connection ( int client_fd)
{
	jack_client_internal_t *client;
	jack_client_connect_ack_request_t req;
	jack_client_connect_ack_result_t res;

	if (read (client_fd, &req, sizeof (req)) != sizeof (req)) {
		jack_error ("cannot read ACK connection request from client");
		return -1;
	}

	if ((client = jack_client_internal_by_id (req.client_id))
	    == NULL) {
		jack_error ("unknown client ID in ACK connection request");
		return -1;
	}

	client->event_fd = client_fd;
	VERBOSE (this, "new client %s using %d for events", client->control->name,
		 client->event_fd);

	res.status = 0;

	if (write (client->event_fd, &res, sizeof (res)) != sizeof (res)) {
		jack_error ("cannot write ACK connection response to client");
		return -1;
	}

	return 0;
}

void *
jack_engine_t::jack_server_thread_aux (void *arg)
{
	jack_engine_t *engine = (jack_engine_t *) arg;
	return engine->jack_server_thread ();
}

void *
jack_engine_t::jack_server_thread ()

{
	struct sockaddr_un client_addr;
	socklen_t client_addrlen;
	int problemsProblemsPROBLEMS = 0;
	int client_socket;
	int done = 0;
	int i;
	const int fixed_fd_cnt = 3;
	int stop_freewheeling;

	while (!done) {
		JSList* node;
		int clients;

		jack_rdlock_graph (this);

		clients = jack_slist_length (_clients);

		if (_pfd_size < fixed_fd_cnt + clients) {
			if (_pfd) {
				free (_pfd);
			}
			_pfd = (struct pollfd *) malloc (sizeof(struct pollfd) * (fixed_fd_cnt + clients));
		}

		_pfd[0].fd = _fds[0];
		_pfd[0].events = POLLIN|POLLERR;
		_pfd[1].fd = _fds[1];
		_pfd[1].events = POLLIN|POLLERR;
		_pfd[2].fd = _cleanup_fifo[0];
		_pfd[2].events = POLLIN|POLLERR;
		_pfd_max = fixed_fd_cnt;
		
		for (node = _clients; node; node = node->next) {

			jack_client_internal_t* client = (jack_client_internal_t*)(node->data);

			if (client->request_fd < 0 || client->error >= JACK_ERROR_WITH_SOCKETS) {
				continue;
			}
			if( client->control->dead ) {
				_pfd[_pfd_max].fd = client->request_fd;
				_pfd[_pfd_max].events = POLLHUP|POLLNVAL;
				_pfd_max++;
				continue;
			}
			_pfd[_pfd_max].fd = client->request_fd;
			_pfd[_pfd_max].events = POLLIN|POLLPRI|POLLERR|POLLHUP|POLLNVAL;
			_pfd_max++;
		}

		jack_unlock_graph (this);
		
		VERBOSE (this, "start poll on %d fd's", _pfd_max);
		
		/* go to sleep for a long, long time, or until a request
		   arrives, or until a communication channel is broken
		*/

		if (poll (_pfd, _pfd_max, -1) < 0) {
			if (errno == EINTR) {
				continue;
			}
			jack_error ("poll failed (%s)", strerror (errno));
			break;
		}
		
		VERBOSE (this, "server thread back from poll");
		
		/* Stephane Letz: letz@grame.fr : has to be added
		 * otherwise pthread_cancel() does not work on MacOSX */
		pthread_testcancel();


		/* empty cleanup FIFO if necessary */

		if (_pfd[2].revents & ~POLLIN) {
			/* time to die */
			break;
		}

		if (_pfd[2].revents & POLLIN) {
			char c;
			while (read (_cleanup_fifo[0], &c, 1) == 1);
		}

		/* check each client socket before handling other request*/
		
		jack_rdlock_graph (this);

		for (i = fixed_fd_cnt; i < _pfd_max; i++) {

			if (_pfd[i].fd < 0) {
				continue;
			}

			if (_pfd[i].revents & ~POLLIN) {

				jack_client_internal_t *client = jack_get_client_for_fd (_pfd[i].fd);
				if( client ) {
				  if( client->control->active ) {
				    jack_mark_client_socket_error (_pfd[i].fd);
				    jack_engine_signal_problems ();
				  } else {
				    jack_unlock_graph (this);
				    jack_lock_graph (this);
				    jack_client_disconnect_ports( client );
				    jack_remove_client( client );
				    jack_unlock_graph (this);
				    jack_rdlock_graph (this);
				  }
				}

			} else if (_pfd[i].revents & POLLIN) {

				if (handle_external_client_request (_pfd[i].fd)) {
					jack_error ("could not handle external"
						    " client request");
					jack_engine_signal_problems ();
				}
			}
		}

		problemsProblemsPROBLEMS = _problems;

		jack_unlock_graph (this);

		/* need to take write lock since we may/will rip out some clients,
		   and reset _problems
		 */

		stop_freewheeling = 0;

		while (problemsProblemsPROBLEMS) {
			
			VERBOSE (this, "trying to lock graph to remove %d problems", problemsProblemsPROBLEMS);
			jack_lock_graph (this);
			VERBOSE (this, "we have problem clients (problems = %d", problemsProblemsPROBLEMS);


			jack_lock_problems (this);

			jack_remove_clients (&stop_freewheeling);
			if (stop_freewheeling) {
				VERBOSE (this, "need to stop freewheeling once problems are cleared");
			}

			_problems -= problemsProblemsPROBLEMS;
			problemsProblemsPROBLEMS = _problems;
			jack_clear_fifos( );
			jack_unlock_problems (this);

			jack_unlock_graph (this);

			VERBOSE (this, "after removing clients, problems = %d", problemsProblemsPROBLEMS);
		}
		
		if (_freewheeling && stop_freewheeling) {
			jack_stop_freewheeling (0);
		}
			
		/* check the master server socket */

		if (_pfd[0].revents & POLLERR) {
			jack_error ("error on server socket");
			break;
		}
	
		if (_control->engine_ok && _pfd[0].revents & POLLIN) {
			DEBUG ("pfd[0].revents & POLLIN");

			memset (&client_addr, 0, sizeof (client_addr));
			client_addrlen = sizeof (client_addr);

			if ((client_socket =
			     accept (_fds[0],
				     (struct sockaddr *) &client_addr,
				     &client_addrlen)) < 0) {
				jack_error ("cannot accept new connection (%s)",
					    strerror (errno));
			} else if (!_new_clients_allowed || jack_client_create (client_socket) < 0) {
				jack_error ("cannot complete client "
					    "connection process");
				close (client_socket);
			}
		}
		
		/* check the ACK server socket */

		if (_pfd[1].revents & POLLERR) {
			jack_error ("error on server ACK socket");
			break;
		}

		if (_control->engine_ok && _pfd[1].revents & POLLIN) {
			DEBUG ("pfd[1].revents & POLLIN");

			memset (&client_addr, 0, sizeof (client_addr));
			client_addrlen = sizeof (client_addr);

			if ((client_socket =
			     accept (_fds[1],
				     (struct sockaddr *) &client_addr,
				     &client_addrlen)) < 0) {
				jack_error ("cannot accept new ACK connection"
					    " (%s)", strerror (errno));
			} else if (handle_client_ack_connection
				   (client_socket)) {
				jack_error ("cannot complete client ACK "
					    "connection process");
				close (client_socket);
			}
		}
	}

	return 0;
}

int
jack_set_sample_rate_aux (jack_engine_t *engine, jack_nframes_t nframes)
{
	return engine->jack_set_sample_rate (nframes);
}

jack_engine_t::jack_engine_t (int realtime, int rtpriority, int do_mlock, int do_unlock,
		 const char *server_name, int temporary, int verbose,
		 int client_timeout, unsigned int port_max, pid_t wait_pid,
		 jack_nframes_t frame_time_offset, int nozombies, int timeout_count_threshold, int jobs, JSList *drivers)
{
	jack_engine_t *engine;
	unsigned int i;
        char server_dir[PATH_MAX+1] = "";

#ifdef USE_CAPABILITIES
	uid_t uid = getuid ();
	uid_t euid = geteuid ();
#endif /* USE_CAPABILITIES */

	/* before we start allocating resources, make sure that if realtime was requested that we can 
	   actually do it.
	*/

	if (realtime) {
		if (jack_acquire_real_time_scheduling (pthread_self(), 10) != 0) {
			/* can't run realtime - time to bomb */
			throw std::exception();
		}

		jack_drop_real_time_scheduling (pthread_self());

#ifdef USE_MLOCK

		if (do_mlock && (mlockall (MCL_CURRENT | MCL_FUTURE) != 0)) {
			jack_error ("cannot lock down memory for jackd (%s)",
				    strerror (errno));
#ifdef ENSURE_MLOCK
			throw std::exception();
#endif /* ENSURE_MLOCK */
		}
#endif /* USE_MLOCK */
	}

	/* start a thread to display messages from realtime threads */
	jack_messagebuffer_init();

	jack_init_time ();

	/* allocate the engine, zero the structure to ease debugging */
	engine = (jack_engine_t *) calloc (1, sizeof (jack_engine_t));

	_drivers = drivers;
	_driver = NULL;
	_driver_desc = NULL;
	_driver_params = NULL;

	_set_sample_rate = jack_set_sample_rate_aux;
	_set_buffer_size = jack_driver_buffer_size_aux;
	_run_cycle = jack_run_cycle_aux;
	_delay = jack_engine_delay_aux;
	_driver_exit = jack_engine_driver_exit_aux;
	_transport_cycle_start = jack_transport_cycle_start;
	_client_timeout_msecs = client_timeout;
	_timeout_count = 0;
	_problems = 0;

	_next_client_id = 1;	/* 0 is a NULL client ID */
	_port_max = port_max;
	_server_thread = 0;
	_watchdog_thread = 0;
	_rtpriority = rtpriority;
	_silent_buffer = 0;
	_verbose = verbose;
	_server_name = server_name;
	_temporary = temporary;
	_freewheeling = 0;
	_stop_freewheeling = 0;
	_fwclient = 0;
	_feedbackcount = 0;
	_wait_pid = wait_pid;
	_nozombies = nozombies;
	_jobs = jobs;
	_timeout_count_threshold = timeout_count_threshold;
	_removing_clients = 0;
        _new_clients_allowed = 1;

	_session_reply_fd = -1;
	_session_pending_replies = 0;

	_audio_out_cnt = 0;
	_audio_in_cnt = 0;
	_midi_out_cnt = 0;
	_midi_in_cnt = 0;

	jack_engine_reset_rolling_usecs ();
	_max_usecs = 0.0f;

	pthread_rwlock_init (&_client_lock, 0);
	pthread_mutex_init (&_port_lock, 0);
	pthread_mutex_init (&_request_lock, 0);

	pthread_mutexattr_init(&_problem_attr);
	pthread_mutexattr_settype(&_problem_attr, PTHREAD_MUTEX_RECURSIVE_NP );
	pthread_mutex_init (&_problem_lock, &_problem_attr);

	_clients = 0;
	_reserved_client_names = 0;

	_process_graph_list[0] = 0;
	_process_graph_list[1] = 0;
	pthread_mutex_init( &_swap_mutex, NULL );
	_pending_chain = 0;


	_pfd_size = 0;
	_pfd_max = 0;
	_pfd = 0;

	_fifo_size = 16;
	_fifo = (int *) malloc (sizeof (int) * _fifo_size);
	for (i = 0; i < _fifo_size; i++) {
		_fifo[i] = -1;
	}

	if (pipe (_cleanup_fifo)) {
		jack_error ("cannot create cleanup FIFOs (%s)", strerror (errno));
		throw std::exception();
	}

	if (fcntl (_cleanup_fifo[0], F_SETFL, O_NONBLOCK)) {
		jack_error ("cannot set O_NONBLOCK on cleanup read FIFO (%s)", strerror (errno));
		throw std::exception();
	}

	if (fcntl (_cleanup_fifo[1], F_SETFL, O_NONBLOCK)) {
		jack_error ("cannot set O_NONBLOCK on cleanup write FIFO (%s)", strerror (errno));
		throw std::exception();
	}

	_client_activation_counts_init[0] = (_Atomic_word *) malloc( sizeof(_Atomic_word) * JACK_MAX_CLIENTS );
	_client_activation_counts_init[1] = (_Atomic_word *) malloc( sizeof(_Atomic_word) * JACK_MAX_CLIENTS );
	for( i=0; i<JACK_MAX_CLIENTS; i++ ) {
		_client_activation_counts_init[0][i] = 0;
		_client_activation_counts_init[1][i] = 0;
	}

	_port_activation_counts_init[0] = (_Atomic_word *) malloc( sizeof(_Atomic_word) * _port_max );
	_port_activation_counts_init[1] = (_Atomic_word *) malloc( sizeof(_Atomic_word) * _port_max );

	_external_client_cnt = 0;

	srandom (time ((time_t *) 0));

	if (jack_shmalloc (sizeof (jack_control_t)
			   + ((sizeof (jack_port_shared_t) * _port_max)),
			   &_control_shm)) {
		jack_error ("cannot create engine control shared memory "
			    "segment (%s)", strerror (errno));
		throw std::exception();
	}

	if (jack_attach_shm (&_control_shm)) {
		jack_error ("cannot attach to engine control shared memory"
			    " (%s)", strerror (errno));
		jack_destroy_shm (&_control_shm);
		throw std::exception();
	}

	_control = (jack_control_t *)
		jack_shm_addr (&_control_shm);

	/* Setup port type information from builtins. buffer space is
	 * allocated when the driver calls jack_driver_buffer_size().
	 */
	for (i = 0; jack_builtin_port_types[i].type_name[0]; ++i) {

		memcpy (&_control->port_types[i],
			&jack_builtin_port_types[i],
			sizeof (jack_port_type_info_t));

		VERBOSE (this, "registered builtin port type %s",
			 _control->port_types[i].type_name);

		/* the port type id is index into port_types array */
		_control->port_types[i].ptype_id = i;

		/* be sure to initialize mutex correctly */
		pthread_mutex_init (&_port_buffers[i].lock, NULL);

		/* set buffer list info correctly */
		_port_buffers[i].freelist = NULL;
		_port_buffers[i].info = NULL;
		
		/* mark each port segment as not allocated */
		_port_segment[i].index = -1;
		_port_segment[i].attached_at = 0;
	}

	_control->n_port_types = i;

	/* Mark all ports as available */

	for (i = 0; i < _port_max; i++) {
		_control->ports[i].in_use = 0;
		_control->ports[i].id = i;
		_control->ports[i].alias1[0] = '\0';
		_control->ports[i].alias2[0] = '\0';
	}

	/* allocate internal port structures so that we can keep track
	 * of port connections.
	 */
	_internal_ports = (jack_port_internal_t *)
		malloc (sizeof (jack_port_internal_t) * _port_max);

	for (i = 0; i < _port_max; i++) {
		_internal_ports[i].connections = 0;
	}

	if (make_sockets (_server_name, _fds) < 0) {
		jack_error ("cannot create server sockets");
		throw std::exception();
	}

	_control->port_max = _port_max;
	_control->real_time = realtime;
	
	/* leave some headroom for other client threads to run
	   with priority higher than the regular client threads
	   but less than the server. see thread.h for 
	   jack_client_real_time_priority() and jack_client_max_real_time_priority()
	   which are affected by this.
	*/

	_control->client_priority = (realtime
					    ? _rtpriority - 5
					    : 0);
	_control->max_client_priority = (realtime
						? _rtpriority - 1
						: 0);
	_control->do_mlock = do_mlock;
	_control->do_munlock = do_unlock;
	_control->cpu_load = 0;
	_control->xrun_delayed_usecs = 0;
	_control->max_delayed_usecs = 0;
	_control->problems = 0;

	jack_set_clock_source (clock_source);
	_control->clock_source = clock_source;
	_get_microseconds = jack_get_microseconds_pointer();

	VERBOSE (this, "clock source = %s", jack_clock_source_name (clock_source));

	_control->frame_timer.frames = frame_time_offset;
	_control->frame_timer.reset_pending = 0;
	_control->frame_timer.current_wakeup = 0;
	_control->frame_timer.next_wakeup = 0;
	_control->frame_timer.initialized = 0;
	_control->frame_timer.filter_coefficient = 0.01;
	_control->frame_timer.second_order_integrator = 0;
	_control->current_process_chain = 0;
	_control->current_setup_chain = 1;

	for( i=0; i<JACK_MAX_CLIENTS; i++ )
		_control->per_client[i].activation_count = -1;
	


	_first_wakeup = 1;

	_control->buffer_size = 0;
	jack_transport_init ();
	jack_set_sample_rate (0);
	_control->internal = 0;

	_control->has_capabilities = 0;
        
#ifdef JACK_USE_MACH_THREADS
        /* specific resources for server/client real-time thread
	 * communication */
	_servertask = mach_task_self();
	if (task_get_bootstrap_port(_servertask, &_bp)){
		jack_error("Jackd: Can't find bootstrap mach port");
		throw std::exception();
        }
        _portnum = 0;
#endif /* JACK_USE_MACH_THREADS */
        
        
#ifdef USE_CAPABILITIES
	if (uid == 0 || euid == 0) {
		VERBOSE (this, "running with uid=%d and euid=%d, "
			 "will not try to use capabilites",
			 uid, euid);
	} else {
		/* only try to use capabilities if not running as root */
		_control->has_capabilities = check_capabilities ();
		if (_control->has_capabilities == 0) {
			VERBOSE (this, "required capabilities not "
				 "available");
		}
		if (_verbose) {
			size_t size;
			cap_t cap = cap_init();
			capgetp(0, cap);
			VERBOSE (this, "capabilities: %s",
				 cap_to_text(cap, &size));
		}
	}
#endif /* USE_CAPABILITIES */

	_control->engine_ok = 1;

	snprintf (_fifo_prefix, sizeof (_fifo_prefix),
		  "%s/jack-ack-fifo-%d",
		  jack_server_dir (_server_name, server_dir), getpid ());

	_graph_wait_fd = jack_get_fifo_fd (0);

	jack_client_create_thread (NULL, &_server_thread, 0, FALSE,
				   jack_server_thread_aux, this);

}

void
jack_engine_t::jack_engine_delay ( float delayed_usecs)
{
	jack_event_t event;
	
	_control->frame_timer.reset_pending = 1;

	_control->xrun_delayed_usecs = delayed_usecs;

	if (delayed_usecs > _control->max_delayed_usecs)
		_control->max_delayed_usecs = delayed_usecs;

	event.type = XRun;

	//we cant call this currently, because it deadlocks sometimes.
	//i am dropping the graphlock while waiting for a rechain.
	//should work now.
	jack_deliver_event_to_all (&event);
}

void
jack_engine_t::jack_engine_delay_aux ( jack_engine_t *engine, float delayed_usecs)
{
	engine->jack_engine_delay (delayed_usecs);
}
void
jack_engine_t::jack_inc_frame_time ( jack_nframes_t nframes)
{
	jack_frame_timer_t *timer = &_control->frame_timer;
	jack_time_t now = _driver->last_wait_ust; // effective time
	float delta;

	// really need a memory barrier here
	timer->guard1++;

	delta = (int64_t) now - (int64_t) timer->next_wakeup;

	timer->current_wakeup = timer->next_wakeup;
	timer->frames += nframes;
	timer->second_order_integrator += 0.5f * 
		timer->filter_coefficient * delta;	
	timer->next_wakeup = timer->current_wakeup + 
		_driver->period_usecs + 
		(int64_t) floorf ((timer->filter_coefficient * 
				   (delta + timer->second_order_integrator)));
	timer->initialized = 1;

	// might need a memory barrier here
	timer->guard2++;
}

void*
jack_engine_t::jack_engine_freewheel_aux (void *arg)
{
	jack_engine_t* engine = (jack_engine_t *) arg;
	return engine->jack_engine_freewheel ();
}

void*
jack_engine_t::jack_engine_freewheel ()
{
	jack_client_internal_t* client;

	VERBOSE (this, "freewheel thread starting ...");

	/* we should not be running SCHED_FIFO, so we don't 
	   have to do anything about scheduling.
	*/

	client = jack_client_internal_by_id (_fwclient);

	while (!_stop_freewheeling) {

		jack_run_one_cycle (_control->buffer_size, 0.0f);

		if (client && client->error) {
			/* run one cycle() will already have told the server thread
			   about issues, and the server thread will clean up.
			   however, its time for us to depart this world ...
			*/
			break;
		}
	}

	VERBOSE (this, "freewheel came to an end, naturally");
	return 0;
}

int
jack_engine_t::jack_start_freewheeling ( jack_client_id_t client_id)
{
	jack_event_t event;
	jack_client_internal_t *client;

	if (_freewheeling) {
		return 0;
	}

	if (_driver == NULL) {
		jack_error ("cannot start freewheeling without a driver!");
		return -1;
	}

	/* stop driver before telling anyone about it so 
	   there are no more process() calls being handled.
	*/

	if (_driver->stop (_driver)) {
		jack_error ("could not stop driver for freewheeling");
		return -1;
	}

	client = jack_client_internal_by_id (client_id);

	if (client->control->process_cbset || client->control->thread_cb_cbset) {
		_fwclient = client_id;
	}

	_freewheeling = 1;
	_stop_freewheeling = 0;

	event.type = StartFreewheel;
	jack_deliver_event_to_all (&event);
	
	if (jack_client_create_thread (NULL, &_freewheel_thread, 0, FALSE,
				       jack_engine_freewheel_aux, this)) {
		jack_error ("could not start create freewheel thread");
		return -1;
	}

	return 0;
}

int
jack_engine_t::jack_stop_freewheeling ( int engine_exiting)
{
	jack_event_t event;
	void *ftstatus;

	if (!_freewheeling) {
		return 0;
	}

	if (_driver == NULL) {
		jack_error ("cannot start freewheeling without a driver!");
		return -1;
	}

	if (!_freewheeling) {
		VERBOSE (this, "stop freewheel when not freewheeling");
		return 0;
	}

	/* tell the freewheel thread to stop, and wait for it
	   to exit.
	*/

	_stop_freewheeling = 1;

	VERBOSE (this, "freewheeling stopped, waiting for thread");
	pthread_join (_freewheel_thread, &ftstatus);
	VERBOSE (this, "freewheel thread has returned");

	_fwclient = 0;
	_freewheeling = 0;

	_fwclient = 0;
	_freewheeling = 0;

	if (!engine_exiting) {
		/* tell everyone we've stopped */
		
		event.type = StopFreewheel;
		jack_deliver_event_to_all (&event);
		
		/* restart the driver */
		
		if (_driver->start (_driver)) {
			jack_error ("could not restart driver after freewheeling");
			return -1;
		}
	}

	return 0;
}

int
jack_engine_t::jack_check_client_status ()
{
	JSList *node;
	int err = 0;

	/* we are already late, or something else went wrong,
	   so it can't hurt to check the existence of all
	   clients.
	*/
	
	int curr_chain = _control->current_process_chain;

	for (node = _process_graph_list[curr_chain]; node; node = jack_slist_next (node)) 
	{
		jack_client_internal_t *client = (jack_client_internal_t *) node->data;
		
		if (client->control->type == ClientExternal) {
			if (kill (client->control->pid, 0)) {
				VERBOSE (this,
					"client %s has died/exited",
					client->control->name);
				client->error++;
				err++;
			}
			if(client->control->last_status != 0) {
				VERBOSE (this,
					"client %s has nonzero process callback status (%d)\n",
					client->control->name, client->control->last_status);
				client->error++;
				err++;
			}
		}
		
		DEBUG ("client %s errors = %d", client->control->name,
		       client->error);
	}

	return err;
}

int
jack_engine_t::jack_run_one_cycle ( jack_nframes_t nframes,
		    float delayed_usecs)
{
	jack_driver_t* driver = _driver;
	int ret = -1;
	static int consecutive_excessive_delays = 0;
	int curr_chain;

        if (pthread_mutex_trylock (&_swap_mutex) == 0)
        {
                // promote chain changes.
                if( _control->current_process_chain != _pending_chain ) {
                        // we need to signal the server thread here that we switched chain.
                        VERBOSE (this, "======= chain switch nextchain: %d getting lock...", _pending_chain ); 
                        _control->current_setup_chain = _control->current_process_chain;
                        _control->current_process_chain = _pending_chain;
                }

                pthread_mutex_unlock (&_swap_mutex);
        }

	curr_chain = _control->current_process_chain;

	//VERBOSE (this, "running cycle for chain %d", curr_chain ); 

#define WORK_SCALE 1.0f

	if (!_freewheeling && 
	    _control->real_time &&
	    _spare_usecs &&
	    ((WORK_SCALE * _spare_usecs) <= delayed_usecs)) {

		MESSAGE("delay of %.3f usecs exceeds estimated spare"
			 " time of %.3f; restart ...\n",
			 delayed_usecs, WORK_SCALE * _spare_usecs);
		
		if (++consecutive_excessive_delays > 10) {
			jack_error ("too many consecutive interrupt delays "
				    "... engine pausing");
			return -1;	/* will exit the thread loop */
		}

		jack_engine_delay (delayed_usecs);
		
		return 0;

	} else {
		consecutive_excessive_delays = 0;
	}

	if (jack_trylock_problems (this)) {
		VERBOSE (this, "problem-lock-driven null cycle");
		if (!_freewheeling) {
			driver->null_cycle (driver, nframes);
		} else {
			/* don't return too fast */
			usleep (1000);
		}
		return 0;
	}

	if (_problems || (_timeout_count_threshold && (_timeout_count > (1 + _timeout_count_threshold*1000/_driver->period_usecs) ))) {
		VERBOSE (this, "problem-driven null cycle problems=%d", _problems);
		jack_unlock_problems (this);
		if (!_freewheeling) {
			driver->null_cycle (driver, nframes);
		} else {
			/* don't return too fast */
			usleep (1000);
		}
		return 0;
	}
		
	if (!_freewheeling) {
		DEBUG("waiting for driver read\n");
		if (driver->read (driver, nframes)) {
			goto unlock;
		}
	}
	
	DEBUG("run process\n");

	if (jack_engine_process (nframes) == 0) {
		if (!_freewheeling) {
			if (driver->write (driver, nframes)) {
				goto unlock;
			}
		}

	} else {
		DEBUG ("engine process cycle failed");
		jack_check_client_status ();
	}

	jack_engine_post_process ();

	if (delayed_usecs > _control->max_delayed_usecs)
		_control->max_delayed_usecs = delayed_usecs;
	
	ret = 0;

  unlock:
	jack_unlock_problems (this);
	DEBUG("cycle finished, status = %d", ret);

	return ret;
}

void
jack_engine_t::jack_engine_driver_exit ()
{
	jack_driver_t* driver = _driver;

	VERBOSE (this, "stopping driver");
	driver->stop (driver);
	VERBOSE (this, "detaching driver");
	driver->detach (driver, this);

	/* tell anyone waiting that the driver exited. */
	kill (_wait_pid, SIGUSR2);
	
	_driver = NULL;
}

void
jack_engine_t::jack_engine_driver_exit_aux (jack_engine_t *engine)
{
	engine->jack_engine_driver_exit ();
}

int
jack_engine_t::jack_run_cycle (jack_nframes_t nframes, float delayed_usecs)
{
	jack_nframes_t left;
	jack_nframes_t b_size = _control->buffer_size;
	jack_frame_timer_t* timer = &_control->frame_timer;
	int no_increment = 0;

	if (_first_wakeup) {

		/* the first wakeup */


		timer->next_wakeup = 
			_driver->last_wait_ust +
			_driver->period_usecs;
		_first_wakeup = 0;
		
		/* if we got an xrun/delayed wakeup on the first cycle,
		   reset the pending flag (we have no predicted wakeups
		   to use), but avoid incrementing the frame timer.
		*/

		if (timer->reset_pending) {
			timer->reset_pending = 0;
			no_increment = 1;
		}
	}

	if (timer->reset_pending) {

		/* post xrun-handling */

		/* don't bother to increment the frame counter, because we missed 1 or more 
		   deadlines in the backend anyway.
		 */

		timer->current_wakeup = _driver->last_wait_ust;
		timer->next_wakeup = _driver->last_wait_ust +
			_driver->period_usecs;

		timer->reset_pending = 0;

	} else {
		
		/* normal condition */

		if (!no_increment) {
			jack_inc_frame_time (nframes);
		}
	}

	if (_verbose) {
		if (nframes != b_size) { 
			VERBOSE (this, 
				"late driver wakeup: nframes to process = %"
				PRIu32 ".", nframes);
		}
	}

	/* run as many cycles as it takes to consume nframes */
	for (left = nframes; left >= b_size; left -= b_size) {
		if (jack_run_one_cycle (b_size, delayed_usecs)) {
			jack_error ("cycle execution failure, exiting");
			return EIO;
		}
	}

	return 0;
}

int
jack_engine_t::jack_run_cycle_aux (jack_engine_t *engine, jack_nframes_t nframes, float delayed_usecs)
{
	return engine->jack_run_cycle (nframes, delayed_usecs);
}

jack_engine_t::~jack_engine_t ()
{
	int i;

	VERBOSE (this, "starting server engine shutdown");

	jack_stop_freewheeling (1);

	_control->engine_ok = 0;	/* tell clients we're going away */

	/* this will wake the server thread and cause it to exit */

	close (_cleanup_fifo[0]);
	close (_cleanup_fifo[1]);

	/* shutdown master socket to prevent new clients arriving */
	shutdown (_fds[0], SHUT_RDWR);
	// close (_fds[0]);

	/* now really tell them we're going away */

	for (i = 0; i < _pfd_max; ++i) {
		shutdown (_pfd[i].fd, SHUT_RDWR);
	}

	if (_driver) {
		jack_driver_t* driver = _driver;

		VERBOSE (this, "stopping driver");
		driver->stop (driver);
		// VERBOSE (this, "detaching driver");
		// driver->detach (driver, engine);
		VERBOSE (this, "unloading driver");
		jack_driver_unload (driver);
		_driver = NULL;
	}

	VERBOSE (this, "freeing shared port segments");
	for (i = 0; i < _control->n_port_types; ++i) {
		jack_release_shm (&_port_segment[i]);
		jack_destroy_shm (&_port_segment[i]);
	}

	/* stop the other engine threads */
	VERBOSE (this, "stopping server thread");

#if JACK_USE_MACH_THREADS 
	// MacOSX pthread_cancel still not implemented correctly in Darwin
	mach_port_t machThread = pthread_mach_thread_np (_server_thread);
	thread_terminate (machThread);
#else
	pthread_cancel (_server_thread);
	pthread_join (_server_thread, NULL);
#endif	

	jack_stop_watchdog ();


	VERBOSE (this, "last xrun delay: %.3f usecs",
		_control->xrun_delayed_usecs);
	VERBOSE (this, "max delay reported by backend: %.3f usecs",
		_control->max_delayed_usecs);

	/* free engine control shm segment */
	_control = NULL;
	VERBOSE (this, "freeing engine shared memory");
	jack_release_shm (&_control_shm);
	jack_destroy_shm (&_control_shm);

	VERBOSE (this, "max usecs: %.3f, engine deleted", _max_usecs);

	free (_fifo );
	free (_client_activation_counts_init[0] );
	free (_client_activation_counts_init[1] );
	free (_port_activation_counts_init[0] );
	free (_port_activation_counts_init[1] );
	free (_internal_ports);

	jack_messagebuffer_exit();
}

void
jack_engine_t::jack_port_clear_connections (
			     jack_port_internal_t *port)
{
	JSList *node, *next;

	for (node = port->connections; node; ) {
		next = jack_slist_next (node);
		jack_port_disconnect_internal (
			((jack_connection_internal_t *)
				 node->data)->source,
			((jack_connection_internal_t *)
			 node->data)->destination);
		node = next;
	}

	jack_slist_free (port->connections);
	port->connections = 0;
}

void
jack_engine_t::jack_deliver_event_to_all ( jack_event_t *event)
{
	JSList *node;

	jack_rdlock_graph (this);
	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_deliver_event (
				    (jack_client_internal_t *) node->data,
				    event);
	}
	jack_unlock_graph (this);
}

jack_client_id_t 
jack_engine_t::jack_engine_get_max_uuid()
{
	JSList *node;
	jack_client_id_t retval = 0;
	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t* client = (jack_client_internal_t*) node->data;
		if( client->control->uid > retval )
			retval = client->control->uid;
	}
	return retval;
}

void jack_engine_t::jack_do_get_client_by_uuid (jack_request_t *req)
{
	JSList *node;
	req->status = -1;
	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t* client = (jack_client_internal_t*) node->data;
		if( client->control->uid == req->x.client_id ) {
			snprintf( req->x.port_info.name, sizeof(req->x.port_info.name), "%s", client->control->name );
			req->status = 0;
			return;
		}
	}
}

void jack_engine_t::jack_do_reserve_name (jack_request_t *req)
{
	jack_reserved_name_t *reservation;
	JSList *node;
	// check is name is free...
	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t* client = (jack_client_internal_t*) node->data;
		if( !strcmp( (char *)client->control->name, req->x.reservename.name )) {
			req->status = -1;
			return;
		}
	}

	reservation = (jack_reserved_name_t *) malloc( sizeof( jack_reserved_name_t ) );
	if( reservation == NULL ) {
		req->status = -1;
		return;
	}

	snprintf( reservation->name, sizeof( reservation->name ), "%s", req->x.reservename.name );
	reservation->uuid = req->x.reservename.uuid;
	_reserved_client_names = jack_slist_append( _reserved_client_names, reservation );

	req->status = 0;
}

int jack_engine_t::jack_send_session_reply (jack_client_internal_t *client )
{
	if (write (_session_reply_fd, (const void *) &client->control->uid, sizeof (client->control->uid))
	    < (ssize_t) sizeof (client->control->uid)) {
		jack_error ("cannot write SessionNotify result " 
			    "to client via fd = %d (%s)", 
			    _session_reply_fd, strerror (errno));
		return -1;
	}
	if (write (_session_reply_fd, (const void *) client->control->name, sizeof (client->control->name))
	    < (ssize_t) sizeof (client->control->name)) {
		jack_error ("cannot write SessionNotify result "
			    "to client via fd = %d (%s)", 
			    _session_reply_fd, strerror (errno));
		return -1;
	}
	if (write (_session_reply_fd, (const void *) client->control->session_command, 
				sizeof (client->control->session_command))
	    < (ssize_t) sizeof (client->control->session_command)) {
		jack_error ("cannot write SessionNotify result "
			    "to client via fd = %d (%s)", 
			    _session_reply_fd, strerror (errno));
		return -1;
	}
	if (write (_session_reply_fd, (const void *) ( & client->control->session_flags ), 
				sizeof (client->control->session_flags))
	    < (ssize_t) sizeof (client->control->session_flags)) {
		jack_error ("cannot write SessionNotify result "
			    "to client via fd = %d (%s)", 
			    _session_reply_fd, strerror (errno));
		return -1;
	}

	return 0;
}

int
jack_engine_t::jack_do_session_notify ( jack_request_t *req, int reply_fd )
{
	JSList *node;
	jack_event_t event;
  
	int reply;
	jack_client_id_t finalizer=0;
        struct stat sbuf;

	if (_session_reply_fd != -1) {
		// we should have a notion of busy or somthing.
		// just sending empty reply now.
		goto send_final;
	}

	_session_reply_fd = reply_fd;
	_session_pending_replies = 0;

	event.type = SaveSession;
	event.y.n = req->x.session.type;
 	
	/* GRAPH MUST BE LOCKED : see callers of jack_send_connection_notification() 
	 */

	// make sure all uuids are set.
	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t* client = (jack_client_internal_t*) node->data;
		if( client->control->uid == 0 ) {
			client->control->uid=jack_engine_get_max_uuid( ) + 1;
		}
	}

        if (stat (req->x.session.path, &sbuf) != 0 || !S_ISDIR (sbuf.st_mode)) {
                jack_error ("session parent directory (%s) does not exist", req->x.session.path);
                goto send_final;
        }

	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t* client = (jack_client_internal_t*) node->data;
		if (client->control->session_cbset) {

			// in case we only want to send to a special client.
			// uuid assign is still complete. not sure if thats necessary.
			if( (req->x.session.target[0] != 0) && strcmp(req->x.session.target, (char *)client->control->name) )
				continue;

                        /* the caller of jack_session_notify() is required to have created the session dir
                         */
                        
                        if (req->x.session.path[strlen(req->x.session.path)-1] == '/') {
                                snprintf (event.x.name, sizeof (event.x.name), "%s%s/", req->x.session.path, client->control->name );
                        } else {
                                snprintf (event.x.name, sizeof (event.x.name), "%s/%s/", req->x.session.path, client->control->name );
                        }
			if (mkdir (event.x.name, 0777) != 0) {
                                jack_error ("cannot create session directory (%s) for client %s: %s",
                                            event.x.name, client->control->name, strerror (errno));
                                break;
                        }
			reply = jack_deliver_event (client, &event);

			if (reply == 1) {
				// delayed reply
				_session_pending_replies += 1;
				client->session_reply_pending = TRUE;
			} else if (reply == 2) {
				// immediate reply
				if (jack_send_session_reply (client))
					goto error_out;
			}
		} 
	}

	if (_session_pending_replies != 0)
		return 0;

send_final:
	if (write (reply_fd, &finalizer, sizeof (finalizer))
			< (ssize_t) sizeof (finalizer)) {
		jack_error ("cannot write SessionNotify result "
				"to client via fd = %d (%s)", 
				reply_fd, strerror (errno));
		goto error_out;
	}

	_session_reply_fd = -1;
	return 0;
error_out:
	return -3;
}

void jack_engine_t::jack_do_session_reply ( jack_request_t *req )
{
	jack_client_id_t client_id = req->x.client_id;
	jack_client_internal_t *client = jack_client_internal_by_id (client_id);
	jack_client_id_t finalizer=0;

	req->status = 0;

	client->session_reply_pending = 0;

	if (_session_reply_fd == -1) {
		jack_error ("spurious Session Reply");
		return;
	}

	_session_pending_replies -= 1;

	if (jack_send_session_reply (client)) {
		// maybe need to fix all client pendings.
		// but we will just get a set of spurious replies now.
		_session_reply_fd = -1;
		return;
	}

	if (_session_pending_replies == 0) {
		if (write (_session_reply_fd, &finalizer, sizeof (finalizer))
				< (ssize_t) sizeof (finalizer)) {
			jack_error ("cannot write SessionNotify result "
					"to client via fd = %d (%s)", 
					_session_reply_fd, strerror (errno));
			req->status = -1;
		}
		_session_reply_fd = -1;
	}
}

void
jack_engine_t::jack_notify_all_port_interested_clients ( jack_client_id_t src, jack_client_id_t dst, jack_port_id_t a, jack_port_id_t b, int connected)
{
	JSList *node;
	jack_event_t event;
  
	event.type = (connected ? PortConnected : PortDisconnected);
	event.x.self_id = a;
	event.y.other_id = b;
 	
	/* GRAPH MUST BE LOCKED : see callers of jack_send_connection_notification() 
	 */

	jack_client_internal_t* src_client = jack_client_internal_by_id (src);
	jack_client_internal_t* dst_client = jack_client_internal_by_id (dst);

	for (node = _clients; node; node = jack_slist_next (node)) {
		jack_client_internal_t* client = (jack_client_internal_t*) node->data;
		if (src_client != client &&  dst_client  != client && client->control->port_connect_cbset != FALSE) {
			
			/* one of the ports belong to this client or it has a port connect callback */
			jack_deliver_event (client, &event);
		} 
	}
}

void
jack_engine_t::jack_driver_do_reorder( jack_client_t *client, jack_event_t *event )
{
  JSList *pnode;
  int setup_chain = (client->engine->current_setup_chain);

  //jack_slist_free( client->ports_rt[setup_chain] );
  //client->ports_rt[setup_chain] = NULL;

  pthread_mutex_lock( &client->ports_mutex );
  for( pnode=client->ports_locked; pnode; pnode=jack_slist_next(pnode) ) {
    jack_port_t *port = (jack_port_t *) pnode->data;

    jack_slist_free( port->connections_rt[setup_chain] );
    port->connections_rt[setup_chain] = jack_slist_copy( port->connections_locked );
    //client->ports_rt[setup_chain] = jack_slist_append( client->ports_rt[setup_chain], port );
  }
  pthread_mutex_unlock( &client->ports_mutex );
}
int
jack_engine_t::jack_deliver_event ( jack_client_internal_t *client,
		    jack_event_t *event)
{
	char status=0;

	/* caller must hold the graph lock */

	DEBUG ("delivering event (type %d)", event->type);

	/* we are not RT-constrained here, so use kill(2) to beef up
	   our check on a client's continued well-being
	*/

	if (client->control->dead || client->error >= JACK_ERROR_WITH_SOCKETS 
	    || (client->control->type == ClientExternal && kill (client->control->pid, 0))) {
		DEBUG ("client %s is dead - no event sent",
		       client->control->name);
		return 0;
	}

	DEBUG ("client %s is still alive", client->control->name);

	if (jack_client_is_internal (client)) {

		switch (event->type) {
		case PortConnected:
		case PortDisconnected:
			jack_client_handle_port_connection
				(client->private_client, event);
			break;

		case BufferSizeChange:
			jack_client_fix_port_buffers
				(client->private_client);

			if (client->control->bufsize_cbset) {
				client->private_client->bufsize
					(event->x.n,
					 client->private_client->bufsize_arg);
			}
			break;

		case SampleRateChange:
			if (client->control->srate_cbset) {
				client->private_client->srate
					(event->x.n,
					 client->private_client->srate_arg);
			}
			break;

		case GraphReordered:
			if (client->control->type == ClientInternal) {
				jack_handle_reorder( client->private_client, event );
			} else {
				jack_driver_do_reorder( client->private_client, event );
				if (client->control->graph_order_cbset) {
					client->private_client->graph_order
						(client->private_client->graph_order_arg);
				}
			}
			break;

		case XRun:
			if (client->control->xrun_cbset) {
				client->private_client->xrun
					(client->private_client->xrun_arg);
			}
			break;

		default:
			/* internal clients don't need to know */
			break;
		}

	} else {

		if (client->control->active) {

			/* there's a thread waiting for events, so
			 * it's worth telling the client */

			DEBUG ("engine writing on event fd");

			if (write (client->event_fd, event, sizeof (*event))
			    != sizeof (*event)) {
				jack_error ("cannot send event to client [%s]"
					    " (%s)", client->control->name,
					    strerror (errno));
				client->error += JACK_ERROR_WITH_SOCKETS;
				jack_engine_signal_problems ();
			}

 			if (client->error) {
 				status = -1;
 			} else {
 				// then we check whether there really is an error.... :)
 
 				struct pollfd pfd[1];
 				pfd[0].fd = client->event_fd;
 				pfd[0].events = POLLERR|POLLIN|POLLHUP|POLLNVAL;
 				jack_time_t poll_timeout = JACKD_CLIENT_EVENT_TIMEOUT;
 				int poll_ret;
				jack_time_t then = jack_get_microseconds ();
				jack_time_t now;
				
#ifdef __linux
			again:
#endif
				VERBOSE (this,"client event poll on %d for %s starts at %lld", 
					client->event_fd, client->control->name, then);
 				if ((poll_ret = poll (pfd, 1, poll_timeout)) < 0) {
 					DEBUG ("client event poll not ok! (-1) poll returned an error");
 					jack_error ("poll on subgraph processing failed (%s)", strerror (errno));
 					status = -1; 
 				} else {
 
 					DEBUG ("\n\n\n\n\n back from client event poll, revents = 0x%x\n\n\n", pfd[0].revents);
					now = jack_get_microseconds();
					VERBOSE (this,"back from client event poll after %lld usecs", now - then);

 					if (pfd[0].revents & ~POLLIN) {

						/* some kind of OOB socket event */

 						DEBUG ("client event poll not ok! (-2), revents = %d\n", pfd[0].revents);
 						jack_error ("subgraph starting at %s lost client", client->control->name);
 						status = -2; 

 					} else if (pfd[0].revents & POLLIN) {

						/* client responded normally */

 						DEBUG ("client event poll ok!");
 						status = 0;

 					} else if (poll_ret == 0) {

						/* no events, no errors, we woke up because poll()
						   decided that time was up ...
						*/
						
#ifdef __linux		
						if (linux_poll_bug_encountered (then, &poll_timeout)) {
							goto again;
						}
						
						if (poll_timeout < 200) {
							VERBOSE (this, "FALSE WAKEUP skipped, remaining = %lld usec", poll_timeout);
							status = 0;
						} else {
#endif
							DEBUG ("client event poll not ok! (1 = poll timed out, revents = 0x%04x, poll_ret = %d)", pfd[0].revents, poll_ret);
							VERBOSE (this,"client %s did not respond to event type %d in time"
								    "(fd=%d, revents = 0x%04x, timeout was %lld)", 
								    client->control->name, event->type,
								    client->event_fd,
								    pfd[0].revents,
								    poll_timeout);
							status = -2;
#ifdef __linux
						}
#endif
 					}
 				}
  			}

 			if (status == 0) {
 				if (read (client->event_fd, &status, sizeof (status)) != sizeof (status)) {
 					jack_error ("cannot read event response from "
 							"client [%s] (%s)",
 							client->control->name,
 							strerror (errno));
					status = -1;
 				} 

 			} else {
 				jack_error ("bad status (%d) for client %s "
					    "handling event (type = %d)",
 					    status,
					    client->control->name,
					    event->type);
  			}

			if (status<0) {
				client->error += JACK_ERROR_WITH_SOCKETS;
				jack_engine_signal_problems ();
			}
		}
	}
	DEBUG ("event delivered");

	return status;
}

int
jack_engine_t::jack_rechain_graph ()
{
	JSList *node;
	JSList *cnode, *pnode;
	unsigned long n;
	int i;
	int err = 0;
	jack_client_internal_t *client, *subgraph_client;
	jack_event_t event;
        int setup_chain;
	//int upstream_is_jackd;
        pthread_mutex_lock( &_swap_mutex );
	setup_chain = _control->current_setup_chain;

	//jack_clear_fifos (engine, setup_chain);

	subgraph_client = 0;

	VERBOSE (this, "++ jack_rechain_graph(): chain %d", setup_chain );

	event.type = GraphReordered;

	jack_slist_free( _process_graph_list[setup_chain] );
	_process_graph_list[setup_chain] = NULL;
	jack_slist_free( _server_wakeup_list[setup_chain] );
	_server_wakeup_list[setup_chain] = NULL;

	for( i=0; i<JACK_MAX_CLIENTS; i++ )
		_client_activation_counts_init[setup_chain][i] = 0;
	for( i=0; i<_port_max; i++ )
		_port_activation_counts_init[setup_chain][i] = 0;


	// TODO:
	// - determine the set of clients we need to wakeup.
	// - calculate all activation_count intialisers.
	// - handle feedback.

	for (n = 0, node = _clients; node; node = jack_slist_next(node)) {

		client = (jack_client_internal_t *) node->data;

		if (client->control->id != 0)
			if ((!client->control->process_cbset) && (!client->control->thread_cb_cbset)) {
				continue;
			}

		VERBOSE (this, "+++ client is now %s active ? %d",
			((jack_client_internal_t *) node->data)->control->name,
			((jack_client_internal_t *) node->data)->control->active);

		if (client->control->active)
                {
                        int has_output_connections = ( (client->control->id == 0) ? 1 : 0 );

                        jack_slist_free(client->ports_rt[setup_chain]);
                        client->ports_rt[setup_chain] = NULL;

                        for( pnode = client->ports; pnode; pnode=jack_slist_next(pnode) )
                        {
                                jack_port_internal_t *own_port = (jack_port_internal_t *) pnode->data;
                                client->ports_rt[setup_chain]= jack_slist_append( client->ports_rt[setup_chain], own_port );

                                if( own_port->shared->flags & JackPortIsOutput )
                                {
                                        if( own_port->connections != NULL )
                                                has_output_connections = 1;
                                        continue;
                                }

                                for( cnode=own_port->connections; cnode; cnode=jack_slist_next(cnode) )
                                {
                                        jack_connection_internal_t *conn = (jack_connection_internal_t *) cnode->data;
                                        jack_port_internal_t *other_port = conn->source;

                                        VERBOSE (this, "checking port %s...", other_port->shared->name );
                                        if( other_port->shared->client_id == 0 )
                                                //driver ports dont count.
                                                continue;

                                        if( conn->dir != 1 )
                                                continue;

                                        _port_activation_counts_init[setup_chain][own_port->shared->id] += 1;
                                        VERBOSE (this, "counts %d", _port_activation_counts_init[setup_chain][own_port->shared->id]);

                                }
                                VERBOSE (this, "port %s activation_count=%d", own_port->shared->name, 
                                                _port_activation_counts_init[setup_chain][own_port->shared->id] );

                                if( _port_activation_counts_init[setup_chain][own_port->shared->id] != 0 )
                                        _client_activation_counts_init[setup_chain][client->control->id] += 1;
                        }

                        if( has_output_connections == 0 ) {
                                VERBOSE (this, "no outs... adding to driver 0 count" );
                                _client_activation_counts_init[setup_chain][0] += 1;
                        }

                        // ok ... everything counted.. 

                        _process_graph_list[setup_chain] = 
                                jack_slist_append( _process_graph_list[setup_chain], client );

                        client->subgraph_start_fd = jack_get_fifo_fd( client->control->id );

                        if (jack_client_is_internal (client)) {

                                jack_deliver_event (client, &event);

                        } else {
                                event.x.n = client->execution_order;
                                event.y.n = 0;
                                jack_deliver_event (client, &event);
                                n++;
                        }
                }
	}

	// now determine the clients, the server needs to wakeup directly.
	for (node = _process_graph_list[setup_chain]; node; node = jack_slist_next(node)) 
	{
		client = (jack_client_internal_t *) node->data;
		if( client->control->id == 0 )
		  continue;
		VERBOSE (this, "checking client %s activation_count = %d", client->control->name, _client_activation_counts_init[setup_chain][client->control->id] );
		// driver refcount might change after this, we need to delay this check.
		if( _client_activation_counts_init[setup_chain][client->control->id] == 0 )
		{
			// this client needs to be triggered by jackd.
			VERBOSE (this, "added..." );
			_server_wakeup_list[setup_chain] = 
				jack_slist_append( _server_wakeup_list[setup_chain], client );
		}
	}

	// chain is setup.
	// now we need to trigger the swap.

	_pending_chain = setup_chain;
	VERBOSE (this, "chain swap triggered... %d", _pending_chain);

        pthread_mutex_unlock( &_swap_mutex );

	VERBOSE (this, "-- jack_rechain_graph()");

	return err;
}

jack_nframes_t
jack_engine_t::jack_get_port_total_latency (
			     jack_port_internal_t *port, int hop_count,
			     int toward_port)
{
	JSList *node;
	jack_nframes_t latency;
	jack_nframes_t max_latency = 0;

#ifdef DEBUG_TOTAL_LATENCY_COMPUTATION
	char prefix[32];
	int i;

	for (i = 0; i < hop_count; ++i) {
		prefix[i] = '\t';
	}

	prefix[i] = '\0';
#endif

	/* call tree must hold _client_lock. */

	latency = port->shared->latency;

	/* we don't prevent cyclic graphs, so we have to do something
	   to bottom out in the event that they are created.
	*/

	if (hop_count > 8) {
		return latency;
	}

#ifdef DEBUG_TOTAL_LATENCY_COMPUTATION
	jack_info ("%sFor port %s (%s)", prefix, port->shared->name, (toward_port ? "toward" : "away"));
#endif
	
	for (node = port->connections; node; node = jack_slist_next (node)) {

		jack_nframes_t this_latency;
		jack_connection_internal_t *connection;

		connection = (jack_connection_internal_t *) node->data;

		
		if ((toward_port &&
		     (connection->source->shared == port->shared)) ||
		    (!toward_port &&
		     (connection->destination->shared == port->shared))) {

#ifdef DEBUG_TOTAL_LATENCY_COMPUTATION
			jack_info ("%s\tskip connection %s->%s",
				 prefix,
				 connection->source->shared->name,
				 connection->destination->shared->name);
#endif

			continue;
		}

#ifdef DEBUG_TOTAL_LATENCY_COMPUTATION
		jack_info ("%s\tconnection %s->%s ... ", 
			 prefix,
			 connection->source->shared->name,
			 connection->destination->shared->name);
#endif
		/* if we're a destination in the connection, recurse
		   on the source to get its total latency
		*/

		if (connection->destination == port) {

			if (connection->source->shared->flags
			    & JackPortIsTerminal) {
				this_latency = connection->source->
					shared->latency;
			} else {
				this_latency =
					jack_get_port_total_latency (
						connection->source,
						hop_count + 1, 
						toward_port);
			}

		} else {

			/* "port" is the source, so get the latency of
			 * the destination */
			if (connection->destination->shared->flags
			    & JackPortIsTerminal) {
				this_latency = connection->destination->
					shared->latency;
			} else {
				this_latency =
					jack_get_port_total_latency (
						
						connection->destination,
						hop_count + 1, 
						toward_port);
			}
		}

		if (this_latency > max_latency) {
			max_latency = this_latency;
		}
	}

#ifdef DEBUG_TOTAL_LATENCY_COMPUTATION
	jack_info ("%s\treturn %lu + %lu = %lu", prefix, latency, max_latency, latency + max_latency);
#endif	

	return latency + max_latency;
}

void
jack_engine_t::jack_compute_port_total_latency ( jack_port_shared_t* port)
{
	if (port->in_use) {
		port->total_latency =
			jack_get_port_total_latency (
				&_internal_ports[port->id],
				0, !(port->flags & JackPortIsOutput));
	}
}

void
jack_engine_t::jack_compute_all_port_total_latencies ()
{
	jack_port_shared_t *shared = _control->ports;
	unsigned int i;
 	int toward_port;

	for (i = 0; i < _control->port_max; i++) {
		if (shared[i].in_use) {

 			if (shared[i].flags & JackPortIsOutput) {
 				toward_port = FALSE;
 			} else {
 				toward_port = TRUE;
 			}

 			shared[i].total_latency =
 				jack_get_port_total_latency (
 					&_internal_ports[i],
 					0, toward_port);
 		}
 	}
}

/* How the sort works:
 *
 * Each client has a "sortfeeds" list of clients indicating which clients
 * it should be considered as feeding for the purposes of sorting the
 * graph. This list differs from the clients it /actually/ feeds in the
 * following ways:
 *
 * 1. Connections from a client to itself are disregarded
 *
 * 2. Connections to a driver client are disregarded
 *
 * 3. If a connection from A to B is a feedback connection (ie there was
 *    already a path from B to A when the connection was made) then instead
 *    of B appearing on A's sortfeeds list, A will appear on B's sortfeeds
 *    list.
 *
 * If client A is on client B's sortfeeds list, client A must come after
 * client B in the execution order. The above 3 rules ensure that the
 * sortfeeds relation is always acyclic so that all ordering constraints
 * can actually be met. 
 *
 * Each client also has a "truefeeds" list which is the same as sortfeeds
 * except that feedback connections appear normally instead of reversed.
 * This is used to detect whether the graph has become acyclic.
 *
 */ 
 
void
jack_engine_t::jack_sort_graph ()
{
	/* called, obviously, must hold _client_lock */

	VERBOSE (this, "++ jack_sort_graph");
	_clients = jack_slist_sort (_clients,
					   (JCompareFunc) jack_client_sort);
	jack_compute_all_port_total_latencies ();
	jack_rechain_graph ();
	_timeout_count = 0;
	VERBOSE (this, "-- jack_sort_graph");
}

int 
jack_engine_t::jack_client_sort (jack_client_internal_t *a, jack_client_internal_t *b)
{
	/* drivers are forced to the front, ie considered as sources
	   rather than sinks for purposes of the sort */

	if (jack_client_feeds_transitive (a, b) ||
	    (a->control->type == ClientDriver &&
	     b->control->type != ClientDriver)) {
		return -1;
	} else if (jack_client_feeds_transitive (b, a) ||
		   (b->control->type == ClientDriver &&
		    a->control->type != ClientDriver)) {
		return 1;
	} else {
		return 0;
	}
}

/* transitive closure of the relation expressed by the sortfeeds lists. */
int
jack_engine_t::jack_client_feeds_transitive (jack_client_internal_t *source,
			      jack_client_internal_t *dest )
{
	jack_client_internal_t *med;
	JSList *node;
	
	if (jack_slist_find (source->sortfeeds, dest)) {
		return 1;
	}

	for (node = source->sortfeeds; node; node = jack_slist_next (node)) {

		med = (jack_client_internal_t *) node->data;

		if (jack_client_feeds_transitive (med, dest)) {
			return 1;
		}
	}

	return 0;
}

/**
 * Checks whether the graph has become acyclic and if so modifies client
 * sortfeeds lists to turn leftover feedback connections into normal ones.
 * This lowers latency, but at the expense of some data corruption.
 */
void
jack_engine_t::jack_check_acyclic ()
{
	JSList *srcnode, *dstnode, *portnode, *connnode;
	jack_client_internal_t *src, *dst;
	jack_port_internal_t *port;
	jack_connection_internal_t *conn;
	int stuck;
	int unsortedclients = 0;

	VERBOSE (this, "checking for graph become acyclic");

	for (srcnode = _clients; srcnode;
	     srcnode = jack_slist_next (srcnode)) {

		src = (jack_client_internal_t *) srcnode->data;
		src->tfedcount = src->fedcount;
		unsortedclients++;
	}
	
	stuck = FALSE;

	/* find out whether a normal sort would have been possible */
	while (unsortedclients && !stuck) {
	
		stuck = TRUE;

		for (srcnode = _clients; srcnode;
	     	     srcnode = jack_slist_next (srcnode)) {

			src = (jack_client_internal_t *) srcnode->data;
			
			if (!src->tfedcount) {
			
				stuck = FALSE;
				unsortedclients--;
				src->tfedcount = -1;
				
				for (dstnode = src->truefeeds; dstnode;
				     dstnode = jack_slist_next (dstnode)) {
				     
					dst = (jack_client_internal_t *)
						dstnode->data;
					dst->tfedcount--;
				}
			}
		}
	}
	
	if (stuck) {

		VERBOSE (this, "graph is still cyclic" );
	} else {

		VERBOSE (this, "graph has become acyclic");

		/* turn feedback connections around in sortfeeds */
		for (srcnode = _clients; srcnode;
		     srcnode = jack_slist_next (srcnode)) {

			src = (jack_client_internal_t *) srcnode->data;

			for (portnode = src->ports; portnode;
			     portnode = jack_slist_next (portnode)) {

				port = (jack_port_internal_t *) portnode->data;
			
				for (connnode = port->connections; connnode;
				     connnode = jack_slist_next (connnode)) {
				
					conn = (jack_connection_internal_t*)
						connnode->data;
				
					if (conn->dir == -1 )
					
					/*&& 
						conn->srcclient == src) */{
				
						VERBOSE (this,
						"reversing connection from "
						"%s to %s",
						conn->srcclient->control->name,
						conn->dstclient->control->name);
						conn->dir = 1;
						conn->dstclient->sortfeeds = 
						  jack_slist_remove
						    (conn->dstclient->sortfeeds,
						     conn->srcclient);
					     
						conn->srcclient->sortfeeds =
						  jack_slist_prepend
						    (conn->srcclient->sortfeeds,
						     conn->dstclient );
					}
				}
			}
		}
		_feedbackcount = 0;
	}
}

/**
 * Dumps current engine configuration.
 */
void jack_engine_t::jack_dump_configuration( int take_lock)
{
        JSList *clientnode, *portnode, *connectionnode;
	jack_client_internal_t *client;
	jack_client_control_t *ctl;
	jack_port_internal_t *port;
	jack_connection_internal_t* connection;
	int n, m, o;
	//int curr_chain = _control->current_process_chain;
	
	jack_info ("engine.c: <-- dump begins -->");

	if (take_lock) {
		jack_rdlock_graph (this);
	}

	for (n = 0, clientnode = _clients; clientnode;
	     clientnode = jack_slist_next (clientnode)) {
	        client = (jack_client_internal_t *) clientnode->data;
		ctl = client->control;

		jack_info ("client #%d: %s (type: %d, process? %s, thread ? %s"
			 " start=%d",
			 ++n,
			 ctl->name,
			 ctl->type,
			 ctl->process_cbset ? "yes" : "no",
			 client->subgraph_start_fd );

		for(m = 0, portnode = client->ports; portnode;
		    portnode = jack_slist_next (portnode)) {
		        port = (jack_port_internal_t *) portnode->data;

			jack_info("\t port #%d: %s", ++m,
				port->shared->name);

			for(o = 0, connectionnode = port->connections; 
			    connectionnode; 
			    connectionnode =
				    jack_slist_next (connectionnode)) {
			        connection = (jack_connection_internal_t *)
					connectionnode->data;
	
				jack_info("\t\t connection #%d: %s %s",
					++o,
					(port->shared->flags
					 & JackPortIsInput)? "<-": "->",
					(port->shared->flags & JackPortIsInput)?
					connection->source->shared->name:
					connection->destination->shared->name);
			}
		}
	}

	if (take_lock) {
		jack_unlock_graph (this);
	}

	
	jack_info("engine.c: <-- dump ends -->");
}

int 
jack_engine_t::jack_port_do_connect (
		       const char *source_port,
		       const char *destination_port)
{
	jack_connection_internal_t *connection;
	jack_port_internal_t *srcport, *dstport;
	jack_port_id_t src_id, dst_id;
	jack_client_internal_t *srcclient, *dstclient;
	JSList *it;

	if ((srcport = jack_get_port_by_name (source_port)) == NULL) {
		jack_error ("unknown source port in attempted connection [%s]",
			    source_port);
		return -1;
	}

	if ((dstport = jack_get_port_by_name (destination_port))
	    == NULL) {
		jack_error ("unknown destination port in attempted connection"
			    " [%s]", destination_port);
		return -1;
	}

	if ((dstport->shared->flags & JackPortIsInput) == 0) {
		jack_error ("destination port in attempted connection of"
			    " %s and %s is not an input port", 
			    source_port, destination_port);
		return -1;
	}

	if ((srcport->shared->flags & JackPortIsOutput) == 0) {
		jack_error ("source port in attempted connection of %s and"
			    " %s is not an output port",
			    source_port, destination_port);
		return -1;
	}

	if (srcport->shared->ptype_id != dstport->shared->ptype_id) {
		jack_error ("ports used in attemped connection are not of "
			    "the same data type");
		return -1;
	}

	if ((srcclient = jack_client_internal_by_id (
						  srcport->shared->client_id))
	    == 0) {
		jack_error ("unknown client set as owner of port - "
			    "cannot connect");
		return -1;
	}
	
	if (!srcclient->control->active) {
		jack_error ("cannot connect ports owned by inactive clients;"
			    " \"%s\" is not active", srcclient->control->name);
		return -1;
	}

	if ((dstclient = jack_client_internal_by_id (
						  dstport->shared->client_id))
	    == 0) {
		jack_error ("unknown client set as owner of port - cannot "
			    "connect");
		return -1;
	}
	
	if (!dstclient->control->active) {
		jack_error ("cannot connect ports owned by inactive clients;"
			    " \"%s\" is not active", dstclient->control->name);
		return -1;
	}

	for (it = srcport->connections; it; it = it->next) {
		if (((jack_connection_internal_t *)it->data)->destination
		    == dstport) {
			return EEXIST;
		}
	}

	connection = (jack_connection_internal_t *)
		malloc (sizeof (jack_connection_internal_t));

	connection->source = srcport;
	connection->destination = dstport;
	connection->srcclient = srcclient;
	connection->dstclient = dstclient;

	src_id = srcport->shared->id;
	dst_id = dstport->shared->id;

	jack_lock_graph (this);

	if (dstport->connections && !dstport->shared->has_mixdown) {
		jack_port_type_info_t *port_type =
			jack_port_type_info (dstport);
		jack_error ("cannot make multiple connections to a port of"
			    " type [%s]", port_type->type_name);
		free (connection);
		jack_unlock_graph (this);
		return -1;
	} else {

		if (dstclient->control->type == ClientDriver)
		{
			/* Ignore output connections to drivers for purposes
			   of sorting. Drivers are executed first in the sort
			   order anyway, and we don't want to treat graphs
			   such as driver -> client -> driver as containing
			   feedback */
			
			VERBOSE (this,
				 "connect %s and %s (output)",
				 srcport->shared->name,
				 dstport->shared->name);

			connection->dir = 1;

		}
		else if (srcclient != dstclient) {
		
			srcclient->truefeeds = jack_slist_prepend
				(srcclient->truefeeds, dstclient);

			dstclient->fedcount++;				

			if (jack_client_feeds_transitive (dstclient,
							  srcclient ) ||
			    (dstclient->control->type == ClientDriver &&
			     srcclient->control->type != ClientDriver)) {
		    
				/* dest is running before source so
				   this is a feedback connection */
				
				VERBOSE (this,
					 "connect %s and %s (feedback)",
					 srcport->shared->name,
					 dstport->shared->name);
				 
				dstclient->sortfeeds = jack_slist_prepend
					(dstclient->sortfeeds, srcclient);

				connection->dir = -1;
				_feedbackcount++;
				VERBOSE (this,
					 "feedback count up to %d",
					 _feedbackcount);

			} else {
		
				/* this is not a feedback connection */

				VERBOSE (this,
					 "connect %s and %s (forward)",
					 srcport->shared->name,
					 dstport->shared->name);

				srcclient->sortfeeds = jack_slist_prepend
					(srcclient->sortfeeds, dstclient);

				connection->dir = 1;
			}
		}
		else
		{
			/* this is a connection to self */

			VERBOSE (this,
				 "connect %s and %s (self)",
				 srcport->shared->name,
				 dstport->shared->name);
			
			connection->dir = 0;
		}

		dstport->connections =
			jack_slist_prepend (dstport->connections, connection);
		srcport->connections =
			jack_slist_prepend (srcport->connections, connection);
		
		DEBUG ("actually sorted the graph...");

		jack_send_connection_notification (
						   srcport->shared->client_id,
						   src_id, dst_id, TRUE);
		

		jack_send_connection_notification (
						   dstport->shared->client_id,
						   dst_id, src_id, TRUE);
						   
		/* send a port connection notification just once to everyone who cares excluding clients involved in the connection */

		jack_notify_all_port_interested_clients (srcport->shared->client_id, dstport->shared->client_id, src_id, dst_id, 1);

		jack_sort_graph ();
	}

	jack_unlock_graph (this);

	return 0;
}

int
jack_engine_t::jack_port_disconnect_internal ( 
			       jack_port_internal_t *srcport, 
			       jack_port_internal_t *dstport )

{
	JSList *node;
	jack_connection_internal_t *connect;
	int ret = -1;
	jack_port_id_t src_id, dst_id;
	int check_acyclic = _feedbackcount;

	/* call tree **** MUST HOLD **** _client_lock. */
	for (node = srcport->connections; node;
	     node = jack_slist_next (node)) {

		connect = (jack_connection_internal_t *) node->data;

		if (connect->source == srcport &&
		    connect->destination == dstport) {

			VERBOSE (this, "DIS-connect %s and %s",
				 srcport->shared->name,
				 dstport->shared->name);
			
			srcport->connections =
				jack_slist_remove (srcport->connections,
						   connect);
			dstport->connections =
				jack_slist_remove (dstport->connections,
						   connect);

			src_id = srcport->shared->id;
			dst_id = dstport->shared->id;

			/* this is a bit harsh, but it basically says
			   that if we actually do a disconnect, and
			   its the last one, then make sure that any
			   input monitoring is turned off on the
			   srcport. this isn't ideal for all
			   situations, but it works better for most of
			   them.
			*/
			if (srcport->connections == NULL) {
				srcport->shared->monitor_requests = 0;
			}

			jack_send_connection_notification (
				srcport->shared->client_id, src_id,
				dst_id, FALSE);
			jack_send_connection_notification (
				dstport->shared->client_id, dst_id,
				src_id, FALSE);

			/* send a port connection notification just once to everyone who cares excluding clients involved in the connection */
			
			jack_notify_all_port_interested_clients (srcport->shared->client_id, dstport->shared->client_id, src_id, dst_id, 0);

			if (connect->dir) {
			
				jack_client_internal_t *src;
				jack_client_internal_t *dst;
			
				src = jack_client_internal_by_id 
					(srcport->shared->client_id);

				dst =  jack_client_internal_by_id
					(dstport->shared->client_id);
								    
				src->truefeeds = jack_slist_remove
					(src->truefeeds, dst);

				dst->fedcount--;					
				
				if (connect->dir == 1) {
					/* normal connection: remove dest from
					   source's sortfeeds list */ 
					src->sortfeeds = jack_slist_remove
						(src->sortfeeds, dst);
				} else {
					/* feedback connection: remove source
					   from dest's sortfeeds list */
					dst->sortfeeds = jack_slist_remove
						(dst->sortfeeds, src);
					_feedbackcount--;
					VERBOSE (this,
						 "feedback count down to %d",
						 _feedbackcount);
					
				}
			} /* else self-connection: do nothing */

                        //XXX: need proper refcounting on these.
			//free (connect);
			ret = 0;
			break;
		}
	}

	if (check_acyclic) {
		jack_check_acyclic ();
	}
	
	jack_sort_graph ();

	return ret;
}

int
jack_engine_t::jack_port_do_disconnect_all (
			     jack_port_id_t port_id)
{
	if (port_id >= _control->port_max) {
		jack_error ("illegal port ID in attempted disconnection [%"
			    PRIu32 "]", port_id);
		return -1;
	}

	VERBOSE (this, "clear connections for %s",
		 _internal_ports[port_id].shared->name);

	jack_lock_graph (this);
	jack_port_clear_connections (&_internal_ports[port_id]);
	jack_sort_graph ();
	jack_unlock_graph (this);

	return 0;
}

int 
jack_engine_t::jack_port_do_disconnect (
			 const char *source_port,
			 const char *destination_port)
{
	jack_port_internal_t *srcport, *dstport;
	int ret = -1;

	if ((srcport = jack_get_port_by_name (source_port)) == NULL) {
		jack_error ("unknown source port in attempted disconnection"
			    " [%s]", source_port);
		return -1;
	}

	if ((dstport = jack_get_port_by_name (destination_port))
	    == NULL) {
		jack_error ("unknown destination port in attempted"
			    " disconnection [%s]", destination_port);
		return -1;
	}

	jack_lock_graph (this);

	ret = jack_port_disconnect_internal (srcport, dstport);

	jack_unlock_graph (this);

	return ret;
}

int 
jack_engine_t::jack_get_fifo_fd ( unsigned int which_fifo)
{
	/* caller must hold client_lock */
	char path[PATH_MAX+1];
	struct stat statbuf;

	snprintf (path, sizeof (path), "%s-%d", _fifo_prefix,
		  which_fifo);

	DEBUG ("%s", path);

	if (stat (path, &statbuf)) {
		if (errno == ENOENT) {

			if (mkfifo(path, 0666) < 0){
				jack_error ("cannot create inter-client FIFO"
					    " [%s] (%s)\n", path,
					    strerror (errno));
				return -1;
			}

		} else {
			jack_error ("cannot check on FIFO %d \n", which_fifo);
			return -1;
		}
	} else {
		if (!S_ISFIFO(statbuf.st_mode)) {
			jack_error ("FIFO %d (%s) already exists, but is not"
				    " a FIFO!\n", which_fifo, path);
			return -1;
		}
	}

	if (which_fifo >= _fifo_size) {
		unsigned int i;

		_fifo = (int *)
			realloc (_fifo,
				 sizeof (int) * (_fifo_size + 16));
		for (i = _fifo_size; i < _fifo_size + 16; i++) {
			_fifo[i] = -1;
		}
		_fifo_size += 16;
	}

	if (_fifo[which_fifo] < 0) {
		if ((_fifo[which_fifo] =
		     open (path, O_RDWR|O_CREAT|O_NONBLOCK, 0666)) < 0) {
			jack_error ("cannot open fifo [%s] (%s)", path,
				    strerror (errno));
			return -1;
		}
		DEBUG ("opened _fifo[%d] == %d (%s)",
		       which_fifo, _fifo[which_fifo], path);
	}

	return _fifo[which_fifo];
}

void
jack_engine_t::jack_clear_fifos ()
{
	/* caller must hold client_lock */

	unsigned int i;
	char buf[16];

	/* this just drains the existing FIFO's of any data left in
	   them by aborted clients, etc. there is only ever going to
	   be 0, 1 or 2 bytes in them, but we'll allow for up to 16.
	*/
	for (i = 0; i < _fifo_size; i++) {
		if (_fifo[i] >= 0) {
			int nread = read (_fifo[i], buf, sizeof (buf));

			if (nread < 0 && errno != EAGAIN) {
				jack_error ("clear fifo[%d] error: %s",
					    i, strerror (errno));
			} 
		}
	}
}

int
jack_engine_t::jack_use_driver ( jack_driver_t *driver)
{
	if (_driver) {
		_driver->detach (_driver, this);
		_driver = 0;
	}

	if (driver) {
		_driver = driver;

		if (driver->attach (driver, this)) {
			_driver = 0;
			return -1;
		}

		_rolling_interval =
			jack_rolling_interval (driver->period_usecs);
	}

	return 0;
}


/* PORT RELATED FUNCTIONS */


jack_port_id_t
jack_engine_t::jack_get_free_port ()
{
	jack_port_id_t i;

	pthread_mutex_lock (&_port_lock);

	for (i = 0; i < _port_max; i++) {
		if (_control->ports[i].in_use == 0) {
			_control->ports[i].in_use = 1;
			break;
		}
	}
	
	pthread_mutex_unlock (&_port_lock);
	
	if (i == _port_max) {
		return (jack_port_id_t) -1;
	}

	return i;
}

void
jack_engine_t::jack_port_release ( jack_port_internal_t *port)
{
	pthread_mutex_lock (&_port_lock);
	port->shared->in_use = 0;
	port->shared->alias1[0] = '\0';
	port->shared->alias2[0] = '\0';

	if (port->buffer_info) {
		jack_port_buffer_list_t *blist =
			jack_port_buffer_list (port);
		pthread_mutex_lock (&blist->lock);
		blist->freelist =
			jack_slist_prepend (blist->freelist,
					    port->buffer_info);
		port->buffer_info = NULL;
		pthread_mutex_unlock (&blist->lock);
	}
	pthread_mutex_unlock (&_port_lock);
}

jack_port_internal_t *
jack_engine_t::jack_get_port_internal_by_name ( const char *name)
{
	jack_port_id_t id;

	pthread_mutex_lock (&_port_lock);

	for (id = 0; id < _port_max; id++) {
		if (jack_port_name_equals (&_control->ports[id], name)) {
			break;
		}
	}

	pthread_mutex_unlock (&_port_lock);
	
	if (id != _port_max) {
		return &_internal_ports[id];
	} else {
		return NULL;
	}
}

int
jack_engine_t::jack_port_do_register ( jack_request_t *req, int internal)
{
	jack_port_id_t port_id;
	jack_port_shared_t *shared;
	jack_port_internal_t *port;
	jack_client_internal_t *client;
	unsigned long i;
	char *backend_client_name;
	size_t len;

	for (i = 0; i < _control->n_port_types; ++i) {
		if (strcmp (req->x.port_info.type,
			    _control->port_types[i].type_name) == 0) {
			break;
		}
	}

	if (i == _control->n_port_types) {
		jack_error ("cannot register a port of type \"%s\"",
			    req->x.port_info.type);
		return -1;
	}

	jack_lock_graph (this);
	if ((client = jack_client_internal_by_id (
						  req->x.port_info.client_id))
	    == NULL) {
		jack_error ("unknown client id in port registration request");
		jack_unlock_graph (this);
		return -1;
	}

	if ((port = jack_get_port_by_name(req->x.port_info.name)) != NULL) {
		jack_error ("duplicate port name in port registration request");
		jack_unlock_graph (this);
		return -1;
	}

	if ((port_id = jack_get_free_port ()) == (jack_port_id_t) -1) {
		jack_error ("no ports available!");
		jack_unlock_graph (this);
		return -1;
	}

	shared = &_control->ports[port_id];

	if (!internal || !_driver) {
		goto fallback;
        }

        /* if the port belongs to the backend client, do some magic with names 
         */

	backend_client_name = (char *) _driver->internal_client->control->name;
	len = strlen (backend_client_name);

	if (strncmp (req->x.port_info.name, backend_client_name, len) != 0) {
		goto fallback;
        }

	/* use backend's original as an alias, use predefined names */

	if (strcmp(req->x.port_info.type, JACK_DEFAULT_AUDIO_TYPE) == 0) {
		if ((req->x.port_info.flags & (JackPortIsPhysical|JackPortIsInput)) == (JackPortIsPhysical|JackPortIsInput)) {
			snprintf (shared->name, sizeof (shared->name), JACK_BACKEND_ALIAS ":playback_%d", ++_audio_out_cnt);
			strcpy (shared->alias1, req->x.port_info.name);
			goto next;
		} 
		else if ((req->x.port_info.flags & (JackPortIsPhysical|JackPortIsOutput)) == (JackPortIsPhysical|JackPortIsOutput)) {
			snprintf (shared->name, sizeof (shared->name), JACK_BACKEND_ALIAS ":capture_%d", ++_audio_in_cnt);
			strcpy (shared->alias1, req->x.port_info.name);
			goto next;
		}
	}

#if 0 // do not do this for MIDI

	else if (strcmp(req->x.port_info.type, JACK_DEFAULT_MIDI_TYPE) == 0) {
		if ((req->x.port_info.flags & (JackPortIsPhysical|JackPortIsInput)) == (JackPortIsPhysical|JackPortIsInput)) {
			snprintf (shared->name, sizeof (shared->name), JACK_BACKEND_ALIAS ":midi_playback_%d", ++_midi_out_cnt);
			strcpy (shared->alias1, req->x.port_info.name);
			goto next;
		} 
		else if ((req->x.port_info.flags & (JackPortIsPhysical|JackPortIsOutput)) == (JackPortIsPhysical|JackPortIsOutput)) {
			snprintf (shared->name, sizeof (shared->name), JACK_BACKEND_ALIAS ":midi_capture_%d", ++_midi_in_cnt);
			strcpy (shared->alias1, req->x.port_info.name);
			goto next;
		}
	}
#endif

fallback:
	strcpy (shared->name, req->x.port_info.name);

next:
	shared->ptype_id = _control->port_types[i].ptype_id;
	shared->client_id = req->x.port_info.client_id;
	shared->flags = req->x.port_info.flags;
	shared->latency = 0;
	shared->monitor_requests = 0;

	port = &_internal_ports[port_id];

	port->shared = shared;
	port->connections = 0;
	port->buffer_info = NULL;
	
	if (jack_port_assign_buffer (port)) {
		jack_error ("cannot assign buffer for port");
		jack_port_release (&_internal_ports[port_id]);
		jack_unlock_graph (this);
		return -1;
	}

	client->ports = jack_slist_prepend (client->ports, port);
	if( client->control->active )
		jack_port_registration_notify (port_id, TRUE);
	jack_unlock_graph (this);

	VERBOSE (this, "registered port %s, offset = %u",
		 shared->name, (unsigned int)shared->offset);

	req->x.port_info.port_id = port_id;

	return 0;
}

int
jack_engine_t::jack_port_do_unregister ( jack_request_t *req)
{
	jack_client_internal_t *client;
	jack_port_shared_t *shared;
	jack_port_internal_t *port;

	if (req->x.port_info.port_id < 0 ||
	    req->x.port_info.port_id > _port_max) {
		jack_error ("invalid port ID %" PRIu32
			    " in unregister request",
			    req->x.port_info.port_id);
		return -1;
	}

	shared = &_control->ports[req->x.port_info.port_id];

	if (shared->client_id != req->x.port_info.client_id) {
		jack_error ("Client %" PRIu32
			    " is not allowed to remove port %s",
			    req->x.port_info.client_id, shared->name);
		return -1;
	}

	jack_lock_graph (this);
	if ((client = jack_client_internal_by_id (shared->client_id))
	    == NULL) {
		jack_error ("unknown client id in port registration request");
		jack_unlock_graph (this);
		return -1;
	}

	port = &_internal_ports[req->x.port_info.port_id];

	jack_port_clear_connections (port);
	jack_port_release (
			   &_internal_ports[req->x.port_info.port_id]);
	
	client->ports = jack_slist_remove (client->ports, port);
	jack_port_registration_notify (req->x.port_info.port_id,
				       FALSE);
	jack_unlock_graph (this);

	return 0;
}

int
jack_engine_t::jack_do_get_port_connections ( jack_request_t *req,
			      int reply_fd)
{
	jack_port_internal_t *port;
	JSList *node;
	unsigned int i;
	int ret = -1;
	int internal = FALSE;

	jack_rdlock_graph (this);

	port = &_internal_ports[req->x.port_info.port_id];

	DEBUG ("Getting connections for port '%s'.", port->shared->name);

	req->x.port_connections.nports = jack_slist_length (port->connections);
	req->status = 0;

	/* figure out if this is an internal or external client */

	for (node = _clients; node; node = jack_slist_next (node)) {
		
		if (((jack_client_internal_t *) node->data)->request_fd
		    == reply_fd) {
			internal = jack_client_is_internal(
				(jack_client_internal_t *) node->data);
			break;
		}
	}

	if (!internal) {
		if (write (reply_fd, req, sizeof (*req))
		    < (ssize_t) sizeof (req)) {
			jack_error ("cannot write GetPortConnections result "
				    "to client via fd = %d (%s)", 
				    reply_fd, strerror (errno));
			goto out;
		}
	} else {
		req->x.port_connections.ports = (const char**)
			malloc (sizeof (char *)
				* req->x.port_connections.nports);
	}

	if (req->type == GetPortConnections) {
		
		for (i = 0, node = port->connections; node;
		     node = jack_slist_next (node), ++i) {

			jack_port_id_t port_id;
			
			if (((jack_connection_internal_t *) node->data)->source
			    == port) {
				port_id = ((jack_connection_internal_t *)
					   node->data)->destination->shared->id;
			} else {
				port_id = ((jack_connection_internal_t *)
					   node->data)->source->shared->id;
			}
			
			if (internal) {

				/* internal client asking for
				 * names. store in malloc'ed space,
				 * client frees
				 */
			        char **ports = (char **) req->x.port_connections.ports;

				ports[i] =
					_control->ports[port_id].name;

			} else {

				/* external client asking for
				 * names. we write the port id's to
				 * the reply fd.
				 */
				if (write (reply_fd, &port_id,
					   sizeof (port_id))
				    < (ssize_t) sizeof (port_id)) {
					jack_error ("cannot write port id "
						    "to client");
					goto out;
				}
			}
		}
	}

	ret = 0;

  out:
	req->status = ret;
	jack_unlock_graph (this);
	return ret;
}

void
jack_engine_t::jack_port_registration_notify (
			       jack_port_id_t port_id, int yn)
{
	jack_event_t event;
	jack_client_internal_t *client;
	JSList *node;

	event.type = (yn ? PortRegistered : PortUnregistered);
	event.x.port_id = port_id;
	
	for (node = _clients; node; node = jack_slist_next (node)) {
		
		client = (jack_client_internal_t *) node->data;

		if (!client->control->active) {
			continue;
		}

		if (client->control->port_register_cbset) {
			if (jack_deliver_event (client, &event)) {
				jack_error ("cannot send port registration"
					    " notification to %s (%s)",
					     client->control->name,
					    strerror (errno));
			}
		}
	}
}

void
jack_engine_t::jack_client_registration_notify (
				 const char* name, int yn)
{
	jack_event_t event;
	jack_client_internal_t *client;
	JSList *node;

	event.type = (yn ? ClientRegistered : ClientUnregistered);
	snprintf (event.x.name, sizeof (event.x.name), "%s", name);
	
	for (node = _clients; node; node = jack_slist_next (node)) {
		
		client = (jack_client_internal_t *) node->data;

		if (!client->control->active) {
			continue;
		}

		if (strcmp ((char*) client->control->name, (char*) name) == 0) {
			/* do not notify client of its own registration */
			continue;
		}

		if (client->control->client_register_cbset) {
			if (jack_deliver_event (client, &event)) {
				jack_error ("cannot send client registration"
					    " notification to %s (%s)",
					     client->control->name,
					    strerror (errno));
			}
		}
	}
}

int
jack_engine_t::jack_port_assign_buffer ( jack_port_internal_t *port)
{
	jack_port_buffer_list_t *blist =
		jack_port_buffer_list (port);
	jack_port_buffer_info_t *bi;

	if (port->shared->flags & JackPortIsInput) {
		port->shared->offset = 0;
		return 0;
	}
	
	pthread_mutex_lock (&blist->lock);

	if (blist->freelist == NULL) {
		jack_port_type_info_t *port_type =
			jack_port_type_info (port);
		jack_error ("all %s port buffers in use!",
			    port_type->type_name);
		pthread_mutex_unlock (&blist->lock);
		return -1;
	}

	bi = (jack_port_buffer_info_t *) blist->freelist->data;
	blist->freelist = jack_slist_remove (blist->freelist, bi);

	port->shared->offset = bi->offset;
	port->buffer_info = bi;

	pthread_mutex_unlock (&blist->lock);
	return 0;
}

jack_port_internal_t *
jack_engine_t::jack_get_port_by_name ( const char *name)
{
	jack_port_id_t id;

	/* Note the potential race on "in_use". Other design
	   elements prevent this from being a problem.
	*/

	for (id = 0; id < _port_max; id++) {
		if (_control->ports[id].in_use &&
		    jack_port_name_equals (&_control->ports[id], name)) {
			return &_internal_ports[id];
		}
	}

	return NULL;
}

int
jack_engine_t::jack_send_connection_notification (
				   jack_client_id_t client_id, 
				   jack_port_id_t self_id,
				   jack_port_id_t other_id, int connected)

{
	jack_client_internal_t *client;
 	jack_event_t event;
 
	if ((client = jack_client_internal_by_id (client_id)) == NULL) {
		jack_error ("no such client %" PRIu32
			    " during connection notification", client_id);
		return -1;
	}

	if (client->control->active) {
		event.type = (connected ? PortConnected : PortDisconnected);
		event.x.self_id = self_id;
		event.y.other_id = other_id;
		
		if (jack_deliver_event (client, &event)) {
			jack_error ("cannot send port connection notification"
				    " to client %s (%s)", 
				    client->control->name, strerror (errno));
			return -1;
		}
	}

	return 0;
}

void
jack_engine_t::jack_wake_server_thread ()
{
	char c = 0;
	/* we don't actually care if this fails */
	VERBOSE (this, "waking server thread");
	write (_cleanup_fifo[1], &c, 1);
}

void
jack_engine_t::jack_engine_signal_problems ()
{
	jack_lock_problems (this);
	_problems++;
	jack_unlock_problems (this);
	jack_wake_server_thread ();
}
