/* -*- mode: c; c-file-style: "bsd"; -*- */
/*
 *  Client creation and destruction interfaces for JACK engine.
 *
 *  Copyright (C) 2001-2003 Paul Davis
 *  Copyright (C) 2004 Jack O'Quin
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <jack/internal.h>
#include <jack/engine.h>
#include <jack/messagebuffer.h>
#include <jack/version.h>
#include <jack/driver.h>
#include <sysdeps/poll.h>
#include <sysdeps/ipc.h>

#include "clientengine.h"
#include "transengine.h"

#include "libjack/local.h"

// XXX:
#define PRIu32 "u"
#define PRIu64 "lu"

void
jack_engine_t::jack_client_disconnect_ports (
			      jack_client_internal_t *client)
{
	JSList *node;
	jack_port_internal_t *port;

	/* call tree **** MUST HOLD *** _client_lock */

	for (node = client->ports; node; node = jack_slist_next (node)) {
		port = (jack_port_internal_t *) node->data;
		jack_port_clear_connections (port);
		jack_port_registration_notify (port->shared->id, FALSE);
		jack_port_release (port);
	}

	jack_slist_free (client->ports);
	jack_slist_free (client->truefeeds);
	jack_slist_free (client->sortfeeds);
	client->truefeeds = 0;
	client->sortfeeds = 0;
	client->ports = 0;
}			

int
jack_engine_t::jack_client_do_deactivate (
			   jack_client_internal_t *client, int sort_graph)
{
	jack_event_t event;
	/* caller must hold _client_lock and must have checked for and/or
	 *   cleared all connections held by client. 
	 */
	if( !client->control->active ) {
	  VERBOSE (this,"client %s already deactivated.", client->control->name);
	  return 0;
	}
	VERBOSE (this,"+++ deactivate %s", client->control->name);

	if (!jack_client_is_internal (client) ) {
		DEBUG( "sending disorder event" );
		event.type = GraphReordered;
		event.x.n  = -1;
		event.y.n = -1;
		jack_deliver_event (client, &event);
	}

	client->control->active = FALSE;

	jack_transport_client_exit (client);

	if (!jack_client_is_internal (client) &&
	    _external_client_cnt > 0) {	
		_external_client_cnt--;
	}
	
        int curr_chain = _control->current_process_chain;

	if (sort_graph) {
		jack_sort_graph ();
		while (_control->current_process_chain == curr_chain)
			usleep(1000);
	}


	return 0;
}

int
jack_engine_t::jack_load_client ( jack_client_internal_t *client,
		  const char *so_name)
{
	const char *errstr;
	char path_to_so[PATH_MAX+1];

	snprintf (path_to_so, sizeof (path_to_so), ADDON_DIR "/%s.so", so_name);
	client->handle = dlopen (path_to_so, RTLD_NOW|RTLD_GLOBAL);
	
	if (client->handle == 0) {
		if ((errstr = dlerror ()) != 0) {
			jack_error ("%s", errstr);
		} else {
			jack_error ("bizarre error loading %s", so_name);
		}
		return -1;
	}

	client->initialize = (int (*)(jack_client_t*, const char*)) dlsym (client->handle, "jack_initialize");

	if ((errstr = dlerror ()) != 0) {
		jack_error ("%s has no initialize() function\n", so_name);
		dlclose (client->handle);
		client->handle = 0;
		return -1;
	}

	client->finish = (void (*)(void *)) dlsym (client->handle,
						   "jack_finish");
	
	if ((errstr = dlerror ()) != 0) {
		jack_error ("%s has no finish() function", so_name);
		dlclose (client->handle);
		client->handle = 0;
		return -1;
	}

	return 0;
}

void
jack_engine_t::jack_client_unload (jack_client_internal_t *client)
{
	if (client->handle) {
		if (client->finish) {
			client->finish (client->private_client->process_arg);
		}
		dlclose (client->handle);
	}
}

void
jack_engine_t::jack_zombify_client ( jack_client_internal_t *client)
{
	VERBOSE (this, "removing client \"%s\" from the processing chain",
		 client->control->name);

	/* caller must hold the client_lock */

	/* this stops jack_deliver_event() from contacing this client */

	client->control->dead = TRUE;

	jack_client_disconnect_ports (client);
	jack_client_do_deactivate (client, FALSE);
}

void
jack_engine_t::jack_remove_client ( jack_client_internal_t *client)
{
	JSList *node;
	jack_client_id_t finalizer=0;

	/* caller must write-hold the client lock */

	VERBOSE (this, "removing client \"%s\"", client->control->name);

        if (client->control->type == ClientInternal) {
                /* unload it while its still a regular client */

		jack_client_unload (client);
        }

	/* if its not already a zombie, make it so */

	if (!client->control->dead) {
		jack_zombify_client (client);
	}

	if (client->session_reply_pending) {
		_session_pending_replies -= 1;

		if (_session_pending_replies == 0) {
			if (write (_session_reply_fd, &finalizer, sizeof (finalizer))
					< (ssize_t) sizeof (finalizer)) {
				jack_error ("cannot write SessionNotify result "
						"to client via fd = %d (%s)", 
						_session_reply_fd, strerror (errno));
			}
			_session_reply_fd = -1;
		}
	}

	if (client->control->type == ClientExternal) {

		/* try to force the server thread to return from poll */
	
		close (client->event_fd);
		close (client->request_fd);
		close (client->subgraph_start_fd);
		_fifo[client->control->id] = -1;
	}

	if (client->control->type == ClientInternal) {
		if (client->private_client->rt_thread_ok)
			jack_client_shutdown_rt_thread (client->private_client);
	} 

	for (node = _clients; node; node = jack_slist_next (node)) {
		if (((jack_client_internal_t *) node->data)->control->id
		    == client->control->id) {
			_clients =
				jack_slist_remove_link (_clients, node);
			jack_slist_free_1 (node);
			break;
		}
	}

	jack_client_delete (client);

	/* ignore the driver, which counts as a client. */

	if (_temporary && (jack_slist_length(_clients) <= 1)) {
		if (_wait_pid >= 0) {
                        /* block new clients from being created
                           after we release the lock.
                        */
                        _new_clients_allowed = 0;
			/* tell the waiter we're done
			   to initiate a normal shutdown.
			*/
			VERBOSE (this, "Kill wait pid to stop");
			kill (_wait_pid, SIGUSR2);
                        /* unlock the graph so that the server thread can finish */
                        jack_unlock_graph (this);                        
			sleep (-1);
		} else {
			exit (0);
		}

	}
}

int
jack_engine_t::jack_check_clients ( int with_timeout_check)
{
	/* CALLER MUST HOLD graph read lock */
	

	JSList* node;
	jack_client_internal_t* client;
	int errs = 0;
	int curr_chain = _control->current_process_chain;

	for (node = _process_graph_list[curr_chain]; node; node = jack_slist_next (node)) {

		client = (jack_client_internal_t *) node->data;

		if (client->error) {
			errs++;
			continue;
		}

		if (with_timeout_check) {

			/* we can only consider the timeout a client error if
			 * it actually woke up.  its possible that the kernel
			 * scheduler screwed us up and never woke up the
			 * client in time. sigh.
			 */
			
			VERBOSE (this, "checking client %s: awake at %" PRIu64 " finished at %" PRIu64, 
				 client->control->name,
				 client->control->awake_at,
				 client->control->finished_at);
			jack_per_client_ctl_t *pcl = & (_control->per_client[client->control->id]);
			VERBOSE (this, "triggered at %" PRIu64 " signaled at %" PRIu64, 
				 pcl->triggered_at,
				 pcl->signalled_at );
			
			if (client->control->awake_at > 0) {
				if (client->control->finished_at == 0) {
					jack_time_t now = jack_get_microseconds();

					if ((now - client->control->awake_at) < _driver->period_usecs) {
						/* we give the client a bit of time, to finish the cycle
						 * we assume here, that we dont get signals delivered to this thread.
						 */
						struct timespec wait_time;
						wait_time.tv_sec = 0;
						wait_time.tv_nsec = (_driver->period_usecs - (now - client->control->awake_at)) * 1000;
						VERBOSE (this, "client %s seems to have timed out. we may have mercy of %d ns."  , client->control->name, (int) wait_time.tv_nsec );
						nanosleep (&wait_time, NULL);
					}

					if (client->control->finished_at == 0) {
						client->control->timed_out++;
						client->error++;
						errs++;
						VERBOSE (this, "client %s has timed out", client->control->name);
					} else {
						/*
						 * the client recovered. if this is a single occurence, thats probably fine.
						 * however, we increase the continuous_stream flag.
						 */

						_timeout_count += 1;
					}
				}
			}
		}
	}
		
	if (errs) {
		jack_engine_signal_problems ();
	}

	return errs;
}

void
jack_engine_t::jack_remove_clients ( int* exit_freewheeling_when_done)
{
	JSList *tmp, *node;
	int need_sort = FALSE;
	jack_client_internal_t *client;

	/* CALLER MUST HOLD GRAPH LOCK */

	VERBOSE (this, "++ Removing failed clients ...");

	/* remove all dead clients */

	for (node = _clients; node; ) {
		
		tmp = jack_slist_next (node);
		
		client = (jack_client_internal_t *) node->data;

		VERBOSE (this, "client %s error status %d", client->control->name, client->error);
		
		if (client->error) {
			
			if (_freewheeling && client->control->id == _fwclient) {
				VERBOSE (this, "freewheeling client has errors");
				*exit_freewheeling_when_done = 1;
			}
			
			/* if we have a communication problem with the
			   client, remove it. otherwise, turn it into
			   a zombie. the client will/should realize
			   this and will close its sockets.  then
			   we'll end up back here again and will
			   finally remove the client.
			*/
			if (client->error >= JACK_ERROR_WITH_SOCKETS) {
				VERBOSE (this, "removing failed "
					 "client %s state = %s errors"
					 " = %d", 
					 client->control->name,
					 jack_client_state_name (this, client),
					 client->error);
				jack_client_disconnect_ports( (jack_client_internal_t *) node->data);
				jack_remove_client (
						    (jack_client_internal_t *)
						    node->data);
			} else {
				VERBOSE (this, "client failure: "
					 "client %s state = %s errors"
					 " = %d", 
					 client->control->name,
					 jack_client_state_name (this, client),
					 client->error);
				if (!_nozombies) {
					jack_zombify_client (
							     (jack_client_internal_t *)
							     node->data);
					client->error = 0;
				}
			}

			need_sort = TRUE;
		}
		
		node = tmp;
	}

	if (need_sort) {
		_control->problems = 1;
		jack_sort_graph ();
		_control->problems = 0;
	}
	
	jack_engine_reset_rolling_usecs ();

	VERBOSE (this, "-- Removing failed clients ...");
}

jack_client_internal_t *
jack_engine_t::jack_client_by_name ( const char *name)
{
	jack_client_internal_t *client = NULL;
	JSList *node;

	jack_rdlock_graph (this);

	for (node = _clients; node; node = jack_slist_next (node)) {
		if (strcmp ((const char *) ((jack_client_internal_t *)
					    node->data)->control->name,
			    name) == 0) {
			client = (jack_client_internal_t *) node->data;
			break;
		}
	}

	jack_unlock_graph (this);
	return client;
}

jack_client_id_t
jack_engine_t::jack_client_id_by_name ( const char *name)
{
	jack_client_id_t id = 0;	/* NULL client ID */
	JSList *node;

	jack_rdlock_graph (this);

	for (node = _clients; node; node = jack_slist_next (node)) {
		if (strcmp ((const char *) ((jack_client_internal_t *)
					    node->data)->control->name,
			    name) == 0) {
			jack_client_internal_t *client = 
				(jack_client_internal_t *) node->data;
			id = client->control->id;
			break;
		}
	}

	jack_unlock_graph (this);
	return id;
}

jack_client_internal_t *
jack_engine_t::jack_client_internal_by_id ( jack_client_id_t id)
{
	jack_client_internal_t *client = NULL;
	JSList *node;

	/* call tree ***MUST HOLD*** the graph lock */

	for (node = _clients; node; node = jack_slist_next (node)) {

		if (((jack_client_internal_t *) node->data)->control->id
		    == id) {
			client = (jack_client_internal_t *) node->data;
			break;
		}
	}

	return client;
}

int
jack_engine_t::jack_client_name_reserved( const char *name )
{
	JSList *node;
        for (node = _reserved_client_names; node; node = jack_slist_next (node)) {
		jack_reserved_name_t *reservation = (jack_reserved_name_t *) node->data;
		if( !strcmp( reservation->name, name ) )
			return 1;
	}
	return 0;
}

/* generate a unique client name
 *
 * returns 0 if successful, updates name in place
 */
inline int
jack_engine_t::jack_generate_unique_name ( char *name)
{
	int tens, ones;
	int length = strlen (name);

	if (length > JACK_CLIENT_NAME_SIZE - 4) {
		jack_error ("%s exists and is too long to make unique", name);
		return 1;		/* failure */
	}

	/*  generate a unique name by appending "-01".."-99" */
	name[length++] = '-';
	tens = length++;
	ones = length++;
	name[tens] = '0';
	name[ones] = '1';
	name[length] = '\0';
	while (jack_client_by_name (name) || jack_client_name_reserved( name )) {
		if (name[ones] == '9') {
			if (name[tens] == '9') {
				jack_error ("client %s has 99 extra"
					    " instances already", name);
				return 1; /* give up */
			}
			name[tens]++;
			name[ones] = '0';
		} else {
			name[ones]++;
		}
	}
	return 0;
}

int
jack_engine_t::jack_client_name_invalid ( char *name,
			  jack_options_t options, jack_status_t *status)
{
	/* Since this is always called from the server thread, no
	 * other new client will be created at the same time.  So,
	 * testing a name for uniqueness is valid here.  When called
	 * from jack_engine_load_driver() this is not strictly true,
	 * but that seems to be adequately serialized due to engine
	 * startup.  There are no other clients at that point, anyway.
	 */

	if (jack_client_by_name (name) || jack_client_name_reserved(name )) {

		*status = (jack_status_t) (*status | JackNameNotUnique);

		if (options & JackUseExactName) {
			jack_error ("cannot create new client; %s already"
				    " exists", name);
			*status = (jack_status_t) (*status | JackFailure);
			return TRUE;
		}

		if (jack_generate_unique_name(name)) {
			*status = (jack_status_t) (*status | JackFailure);
			return TRUE;
		}
	}

	return FALSE;
}

jack_client_id_t
jack_engine_t::jack_get_client_id( )
{
	int i;
	for( i=0; i<JACK_MAX_CLIENTS; i++ )
		if( _control->per_client[i].activation_count == -1 )
			break;

	jack_get_fifo_fd (i);
	_control->per_client[i].activation_count = 0;

	return i;
}

/* Set up the engine's client internal and control structures for both
 * internal and external clients. */
jack_client_internal_t *
jack_engine_t::jack_setup_client_control ( int fd,
			   ClientType type, const char *name, jack_client_id_t uuid)
{
	jack_client_internal_t *client;

	client = (jack_client_internal_t *)
		malloc (sizeof (jack_client_internal_t));

	client->request_fd = fd;
	client->event_fd = -1;
	client->ports = 0;
	client->truefeeds = 0;
	client->sortfeeds = 0;
	client->execution_order = UINT_MAX;
	client->next_client = NULL;
	client->handle = NULL;
	client->finish = NULL;
	client->error = 0;
        client->ports = NULL;
        client->ports_rt[0] = NULL;
        client->ports_rt[1] = NULL;

	if (type != ClientExternal) {
		
		client->control = (jack_client_control_t *)
			malloc (sizeof (jack_client_control_t));		

	} else {

                if (jack_shmalloc (sizeof (jack_client_control_t), 
				   &client->control_shm)) {
                        jack_error ("cannot create client control block for %s",
				    name);
			free (client);
                        return 0;
                }

		if (jack_attach_shm (&client->control_shm)) {
			jack_error ("cannot attach to client control block "
				    "for %s (%s)", name, strerror (errno));
			jack_destroy_shm (&client->control_shm);
			free (client);
			return 0;
		}

		client->control = (jack_client_control_t *)
			jack_shm_addr (&client->control_shm);
	}

	client->control->type = type;
	client->control->active = 0;
	client->control->dead = FALSE;
	client->control->timed_out = 0;
	client->control->nframes = _control->buffer_size;
	client->control->id = jack_get_client_id();
	client->control->uid = uuid;
	strcpy ((char *) client->control->name, name);
	client->subgraph_start_fd = -1;

	client->session_reply_pending = FALSE;

	client->control->process_cbset = FALSE;
	client->control->bufsize_cbset = FALSE;
	client->control->srate_cbset = FALSE;
	client->control->xrun_cbset = FALSE;
	client->control->port_register_cbset = FALSE;
	client->control->port_connect_cbset = FALSE;
	client->control->graph_order_cbset = FALSE;
	client->control->client_register_cbset = FALSE;
	client->control->thread_cb_cbset = FALSE;
	client->control->thread_init_cbset = FALSE;
	client->control->session_cbset = FALSE;

// XXX: hmm... this shouldnt be necessary. but having em uninit sucks.
#if 0
	if (type != ClientExternal) {
	    client->process = NULL;
	    client->process_arg = NULL;
	    client->bufsize = NULL;
	    client->bufsize_arg = NULL;
	    client->srate = NULL;
	    client->srate_arg = NULL;
	    client->xrun = NULL;
	    client->xrun_arg = NULL;
	    client->port_register = NULL;
	    client->port_register_arg = NULL;
	    client->port_connect = NULL;
	    client->port_connect_arg = NULL;
	    client->graph_order = NULL;
	    client->graph_order_arg = NULL;
	    client->client_register = NULL;
	    client->client_register_arg = NULL;
	    client->thread_cb = NULL;
	    client->thread_cb_arg = NULL;
	}
#endif
	jack_transport_client_new (client);
        
#ifdef JACK_USE_MACH_THREADS
        /* specific resources for server/client real-time thread
	 * communication */
        allocate_mach_serverport(client);
        client->running = FALSE;
#endif

	return client;
}

void
jack_engine_t::jack_ensure_uuid_unique ( jack_client_id_t uuid)
{
	JSList *node;

	jack_lock_graph (this);
	for (node=_clients; node; node=jack_slist_next (node)) {
		jack_client_internal_t *client = (jack_client_internal_t *) node->data;
		if (client->control->uid == uuid)
			client->control->uid = 0;
	}
	jack_unlock_graph (this);
}

/* set up all types of clients */
jack_client_internal_t *
jack_engine_t::setup_client ( ClientType type, char *name, jack_client_id_t uuid,
	      jack_options_t options, jack_status_t *status, int client_fd,
	      const char *object_path, const char *object_data)
{
	/* called with the request_lock */
	jack_client_internal_t *client;

	/* validate client name, generate a unique one if appropriate */
	if (jack_client_name_invalid (name, options, status))
		return NULL;

	if (uuid != 0)
		jack_ensure_uuid_unique (uuid);

	/* create a client struct for this name */
	if ((client = jack_setup_client_control (client_fd,
						 type, name, uuid )) == NULL) {
		*status = (jack_status_t) (*status | JackFailure | JackInitFailure);
		jack_error ("cannot create new client object");
		return NULL;
	}

	/* only for internal clients, driver is already loaded */
	if (type == ClientInternal) {
		if (jack_load_client (client, object_path)) {
			jack_error ("cannot dynamically load client from"
				    " \"%s\"", object_path);
			jack_client_delete (client);
			*status = (jack_status_t) (*status | JackFailure | JackLoadFailure);
			return NULL;
		}
	}

	VERBOSE (this, "new client: %s, id = %" PRIu32
		 " type %d @ %p fd = %d", 
		 client->control->name, client->control->id, 
		 type, client->control, client_fd);

	if (jack_client_is_internal(client)) {

	    // XXX: do i need to lock the graph here ?
	    // i moved this one up in the init process, lets see what happens.

		/* Internal clients need to make regular JACK API
		 * calls, which need a jack_client_t structure.
		 * Create one here.
		 */
		client->private_client =
			jack_client_alloc_internal (client->control, this);

		/* Set up the pointers necessary for the request
		 * system to work.  The client is in the same address
		 * space */

		client->private_client->deliver_request = internal_client_request;
		client->private_client->deliver_arg = this;
	}

	/* add new client to the clients list */
	jack_lock_graph (this);
 	_clients = jack_slist_prepend (_clients, client);
	jack_engine_reset_rolling_usecs ();
	
	if (jack_client_is_internal(client)) {


		jack_unlock_graph (this);

		/* Call its initialization function.  This function
		 * may make requests of its own, so we temporarily
		 * release and then reacquire the request_lock.  */
		if (client->control->type == ClientInternal) {

			pthread_mutex_unlock (&_request_lock);
			if (client->initialize (client->private_client,
						object_data)) {

				/* failed: clean up client data */
				VERBOSE (this,
					 "%s jack_initialize() failed!",
					 client->control->name);
				jack_lock_graph (this);
				jack_remove_client (client);
				jack_unlock_graph (this);
				*status = (jack_status_t) (*status | JackFailure | JackInitFailure);
				client = NULL;
				//JOQ: not clear that all allocated
				//storage has been cleaned up properly.
			}
			pthread_mutex_lock (&_request_lock);
		}

	} else {			/* external client */

		jack_unlock_graph (this);
	}
	
	return client;
}

jack_client_internal_t *
jack_engine_t::jack_create_driver_client ( char *name)
{
	jack_client_connect_request_t req;
	jack_status_t status;
	jack_client_internal_t *client;

	snprintf (req.name, sizeof (req.name), "%s", name);

	pthread_mutex_lock (&_request_lock);
	client = setup_client (ClientDriver, name, 0, JackUseExactName,
			       &status, -1, NULL, NULL);
	pthread_mutex_unlock (&_request_lock);

	return client;
}

jack_status_t
jack_engine_t::handle_unload_client ( jack_client_id_t id)
{
	/* called *without* the request_lock */
	jack_client_internal_t *client;
	jack_status_t status = (jack_status_t) (JackNoSuchClient|JackFailure);

	jack_lock_graph (this);

	if ((client = jack_client_internal_by_id (id))) {
		VERBOSE (this, "unloading client \"%s\"",
			 client->control->name);
		jack_client_disconnect_ports( client );
		jack_client_do_deactivate( client, TRUE );
		jack_remove_client (client);
		status = (jack_status_t) 0;
	}

	jack_unlock_graph (this);

	return status;
}

char *
jack_engine_t::jack_get_reserved_name(  jack_client_id_t uuid )
{
	JSList *node;
        for (node = _reserved_client_names; node; node = jack_slist_next (node)) {
		jack_reserved_name_t *reservation = (jack_reserved_name_t *) node->data;
		if( reservation->uuid== uuid ) {
			char *retval = strdup( reservation->name );
			free( reservation );
			_reserved_client_names = 
				jack_slist_remove( _reserved_client_names, reservation );
			return retval;
		}
	}
	return 0;
}
int
jack_engine_t::jack_client_create ( int client_fd)
{
	/* called *without* the request_lock */
	jack_client_internal_t *client;
	jack_client_connect_request_t req;
	jack_client_connect_result_t res;
	ssize_t nbytes;

	res.status = (jack_status_t) 0;

	nbytes = read (client_fd, &req, sizeof (req));

	if (nbytes == 0) {		/* EOF? */
		jack_error ("cannot read connection request from client");
		return -1;
	}

	/* First verify protocol version (first field of request), if
	 * present, then make sure request has the expected length. */
	if ((nbytes < sizeof (req.protocol_v))
	    || (req.protocol_v != jack_protocol_version)
	    || (nbytes != sizeof (req))) {

		/* JACK protocol incompatibility */
		res.status = (jack_status_t) (res.status|JackFailure|JackVersionError);
		jack_error ("JACK protocol mismatch (%d vs %d)", req.protocol_v, jack_protocol_version);
		if (write (client_fd, &res, sizeof (res)) != sizeof (res)) {
			jack_error ("cannot write client connection response");
		}
		return -1;
	}

	if (!req.load) {		/* internal client close? */

		int rc = -1;
		jack_client_id_t id;

		if ((id = jack_client_id_by_name(req.name))) {
			rc = handle_unload_client (id);
		}
		
		/* close does not send a reply */
		return rc;
	}
	
	pthread_mutex_lock (&_request_lock);
	if( req.uuid ) {
		char *res_name = jack_get_reserved_name( req.uuid );
		if( res_name ) {
			snprintf( req.name, sizeof(req.name), "%s", res_name );
			free(res_name);
		}
	}
	client = setup_client (req.type, req.name, req.uuid,
			       req.options, &res.status, client_fd,
			       req.object_path, req.object_data);
	pthread_mutex_unlock (&_request_lock);
	if (client == NULL) {
		res.status = (jack_status_t) (res.status|JackFailure); /* just making sure */
		return -1;
	}
	res.client_shm_index = client->control_shm.index;
	res.engine_shm_index = _control_shm.index;
	res.realtime = _control->real_time;
	res.realtime_priority = _rtpriority - 1;
	strncpy (res.name, req.name, sizeof(res.name));

#ifdef JACK_USE_MACH_THREADS
	/* Mach port number for server/client communication */
	res.portnum = client->portnum;
#endif
	
	if (jack_client_is_internal(client)) {
		/* the ->control pointers are for an internal client
		   so we know they are the right sized pointers
		   for this server. however, to keep the result
		   structure the same size for both 32 and 64 bit
		   clients/servers, the result structure stores
		   them as 64 bit integer, so we have to do a slightly
		   forced cast here.
		*/
		res.client_control = (uint64_t) ((intptr_t) client->control);
		res.engine_control = (uint64_t) ((intptr_t) _control);
	} else {
		strcpy (res.fifo_prefix, _fifo_prefix);
	}

	if (write (client_fd, &res, sizeof (res)) != sizeof (res)) {
		jack_error ("cannot write connection response to client");
		jack_lock_graph (this);
		client->control->dead = 1;
		jack_remove_client (client);
		jack_unlock_graph (this);
		return -1;
	}

	if (jack_client_is_internal (client)) {
		close (client_fd);
	}

	jack_client_registration_notify ((const char*) client->control->name, 1);

	return 0;
}

int
jack_engine_t::jack_client_activate ( jack_client_id_t id)
{
	jack_client_internal_t *client;
	JSList *node;
	int ret = -1;
	int i;
	jack_event_t event;

	jack_lock_graph (this);

	if ((client = jack_client_internal_by_id (id)))
	{
		VERBOSE( this, "activating client %s", client->control->name );
		client->control->active = TRUE;

		jack_transport_activate(client);

		for (i = 0; i < _control->n_port_types; ++i) {
			event.type = AttachPortSegment;
			event.y.ptid = i;
			jack_deliver_event (client, &event);
		}

		event.type = BufferSizeChange;
		jack_deliver_event (client, &event);

		jack_sort_graph ();

		// send delayed notifications for ports.
		for (node = client->ports; node; node = jack_slist_next (node)) {
			jack_port_internal_t *port = (jack_port_internal_t *) node->data;
			jack_port_registration_notify (port->shared->id, TRUE);
		}

		ret = 0;
	}


	jack_unlock_graph (this);
	return ret;
}	

int
jack_engine_t::jack_client_deactivate ( jack_client_id_t id)
{
	JSList *node;
	int ret = -1;

	jack_lock_graph (this);

	for (node = _clients; node; node = jack_slist_next (node)) {

		jack_client_internal_t *client =
			(jack_client_internal_t *) node->data;

		if (client->control->id == id) {
		        
	        	JSList *portnode;
			jack_port_internal_t *port;

			for (portnode = client->ports; portnode;
			     portnode = jack_slist_next (portnode)) {
				port = (jack_port_internal_t *) portnode->data;
				jack_port_clear_connections (port);
 			}

			ret = jack_client_do_deactivate (client, TRUE);
			break;
		}
	}

	jack_unlock_graph (this);

	return ret;
}	

jack_client_internal_t *
jack_engine_t::jack_get_client_for_fd ( int fd)
{
	/* CALLER MUST HOLD GRAPH LOCK */

	jack_client_internal_t *client = 0;
	JSList *node;

        for (node = _clients; node; node = jack_slist_next (node)) {

                if (jack_client_is_internal((jack_client_internal_t *)
					    node->data)) {
                        continue;
                }

                if (((jack_client_internal_t *) node->data)->request_fd == fd) {
                        client = (jack_client_internal_t *) node->data;
                        break;
                }
        }

	return client;
}

int
jack_engine_t::jack_mark_client_socket_error ( int fd)
{
	/* CALLER MUST HOLD GRAPH LOCK */

	jack_client_internal_t *client = 0;
	JSList *node;

        for (node = _clients; node; node = jack_slist_next (node)) {

                if (jack_client_is_internal((jack_client_internal_t *)
					    node->data)) {
                        continue;
                }

                if (((jack_client_internal_t *) node->data)->request_fd == fd) {
                        client = (jack_client_internal_t *) node->data;
                        break;
                }
        }

        if (client) {
		VERBOSE (this, "marking client %s with SOCKET error state = "
			 "%s errors = %d", client->control->name,
			 jack_client_state_name (this, client),
			 client->error);
		client->error += JACK_ERROR_WITH_SOCKETS;
	}

	return 0;
}

void
jack_engine_t::jack_client_delete ( jack_client_internal_t *client)
{
	jack_client_id_t id = client->control->id;

	jack_client_registration_notify ((const char*) client->control->name, 0);
	

	if (jack_client_is_internal (client)) {

		free (client->private_client);
		free ((void *) client->control);

        } else {

		/* release the client segment, mark it for
		   destruction, and free up the shm registry
		   information so that it can be reused.
		*/

		jack_release_shm (&client->control_shm);
		jack_destroy_shm (&client->control_shm);
        }

	_control->per_client[id].activation_count = -1;

        free (client);

}

void
jack_engine_t::jack_intclient_handle_request ( jack_request_t *req)
{
	jack_client_internal_t *client;

	req->status = 0;
	if ((client = jack_client_by_name (req->x.intclient.name))) {
		req->x.intclient.id = client->control->id;
	} else {
		req->status |= (JackNoSuchClient|JackFailure);
	}
}

void
jack_engine_t::jack_intclient_load_request ( jack_request_t *req)
{
	/* called with the request_lock */
	jack_client_internal_t *client;
	jack_status_t status = (jack_status_t) 0;

	VERBOSE (this, "load internal client %s from %s, init `%s', "
		 "options: 0x%x", req->x.intclient.name,
		 req->x.intclient.path, req->x.intclient.init,
		 req->x.intclient.options);

	client = setup_client (ClientInternal, req->x.intclient.name, 0,
			       (jack_options_t) req->x.intclient.options, &status, -1,
			       req->x.intclient.path, req->x.intclient.init);

	if (client == NULL) {
		status = (jack_status_t) (status | JackFailure);	/* just making sure */
		req->x.intclient.id = 0;
		VERBOSE (this, "load failed, status = 0x%x", status);
	} else {
		req->x.intclient.id = client->control->id;
	}

	req->status = status;
}

void
jack_engine_t::jack_intclient_name_request ( jack_request_t *req)
{
	jack_client_internal_t *client;

	jack_rdlock_graph (this);
	if ((client = jack_client_internal_by_id (
						  req->x.intclient.id))) {
		strncpy ((char *) req->x.intclient.name,
			 (char *) client->control->name,
			 sizeof (req->x.intclient.name));
		req->status = 0;
	} else {
		req->status = (JackNoSuchClient|JackFailure);
	}
	jack_unlock_graph (this);
}

void
jack_engine_t::jack_intclient_unload_request ( jack_request_t *req)
{
	/* Called with the request_lock, but we need to call
	 * handle_unload_client() *without* it. */

	if (req->x.intclient.id) {
		pthread_mutex_unlock (&_request_lock);
		req->status =
			handle_unload_client (req->x.intclient.id);
		pthread_mutex_lock (&_request_lock);
	} else {
		VERBOSE (this, "invalid unload request");
		req->status = JackFailure;
	}
}

