/*
    Copyright (C) 2001 Paul Davis
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software 
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id$
*/

#ifndef __jack_h__
#define __jack_h__

#ifdef __cplusplus
extern "C" {
#endif

#include <jack/types.h>
#include <jack/error.h>

jack_client_t *jack_client_new (const char *client_name);
int             jack_client_close (jack_client_t *client);

int jack_set_process_callback (jack_client_t *, JackProcessCallback, void *arg);
int jack_set_buffer_size_callback (jack_client_t *, JackBufferSizeCallback, void *arg);
int jack_set_sample_rate_callback (jack_client_t *, JackSampleRateCallback, void *arg);
int jack_set_port_registration_callback (jack_client_t *, JackPortRegistrationCallback, void *);
int jack_set_port_monitor_callback (jack_client_t *, JackPortMonitorCallback, void *);

int jack_get_process_start_fd (jack_client_t *);
int jack_get_process_done_fd (jack_client_t *);

int jack_activate (jack_client_t *client);
int jack_deactivate (jack_client_t *client);

/* this creates a new port for the client. 

   a port is an object used for moving data in or out of the client.
   the data may be of any type. ports may be connected to each other
   in various ways.

   a port has a short name, which may be any non-NULL and non-zero
   length string, and is passed as the first argument. a port's full
   name is the name of the client concatenated with a colon (:) and
   then its short name.

   a port has a type, which may be any non-NULL and non-zero length
   string, and is passed as the second argument. for types that are
   not built into the jack API (currently just
   JACK_DEFAULT_AUDIO_TYPE) the client MUST supply a non-zero size
   for the buffer as the fourth argument. for builtin types, the
   fourth argument is ignored.

   a port has a set of flags, enumerated below and passed as the third
   argument in the form of a bitmask created by AND-ing together the
   desired flags. the flags "IsInput" and "IsOutput" are mutually
   exclusive and it is an error to use them both.  

*/

enum JackPortFlags {

     JackPortIsInput = 0x1,
     JackPortIsOutput = 0x2,
     JackPortIsPhysical = 0x4, /* refers to a physical connection */

     /* if JackPortCanMonitor is set, then a call to
	jack_port_request_monitor() makes sense.
	
	Precisely what this means is dependent on the client. A typical
	result of it being called with TRUE as the second argument is
	that data that would be available from an output port (with
	JackPortIsPhysical set) is sent to a physical output connector
	as well, so that it can be heard/seen/whatever.
	
	Clients that do not control physical interfaces
	should never create ports with this bit set.

	Clients that do set this bit must have provided a
	port_monitor callback before creating any ports with
	this bit set.  
     */

     JackPortCanMonitor = 0x8
};	    

#define JACK_DEFAULT_AUDIO_TYPE "32 bit float mono audio"

jack_port_t *
jack_port_register (jack_client_t *,
		     const char *port_name,
		     const char *port_type,
		     unsigned long flags,
		     unsigned long buffer_size);

/* this removes the port from the client */

int jack_port_unregister (jack_client_t *, jack_port_t *);

/* This returns a pointer to the memory area associated with the
   specified port. It can only be called from within the client's
   "process" callback. For an output port, it will be a memory area
   that can be written to; for an input port, it will be an area
   containing the data from the port's connection(s), or
   zero-filled. if there are multiple inbound connections, the data
   will be mixed appropriately.  
*/

void *jack_port_get_buffer (jack_port_t *, nframes_t);

/* these two functions establish and disestablish a connection
   between two ports. when a connection exists, data written 
   to the source port will be available to be read at the destination
   port.

   the types of both ports must be identical to establish a connection.

   the flags of the source port must include PortIsOutput.
   the flags of the destination port must include PortIsInput.
*/

int jack_port_connect (jack_client_t *,
			const char *source_port,
			const char *destination_port);

int jack_port_disconnect (jack_client_t *,
			   const char *source_port,
			   const char *destination_port);

/* A client may call this on a pair of its own ports to 
   semi-permanently wire them together. This means that
   a client that wants to direct-wire an input port to
   an output port can call this and then no longer
   have to worry about moving data between them. Any data
   arriving at the input port will appear automatically
   at the output port.

   The `destination' port must be an output port. The `source'
   port must be an input port. Both ports must belong to
   the same client. You cannot use this to tie ports between
   clients. Thats what a connection is for.
*/

int  jack_port_tie (jack_port_t *dst, jack_port_t *src);

/* This undoes the effect of jack_port_tie(). The port
   should be same as the `destination' port passed to
   jack_port_tie().
*/

int  jack_port_untie (jack_port_t *port);

/* a client may call this function to prevent other objects
   from changing the connection status of the named port.
*/

int jack_port_lock (jack_client_t *, jack_port_t *);
int jack_port_unlock (jack_client_t *, jack_port_t *);


/* if JackPortCanMonitor is set for a port, then this function will
   turn on/off input monitoring for the port.  if JackPortCanMonitor
   is not set, then this function will do nothing.  
*/

int jack_port_request_monitor (jack_client_t *, const char *port_name, int onoff);

/* this returns the sample rate of the jack */

unsigned long jack_get_sample_rate (jack_client_t *);

/* this returns the current maximum size that will
   ever be passed to the "process" callback. it should only
   be used *before* the client has been activated.
*/

nframes_t jack_get_buffer_size (jack_client_t *);

/* This function returns a NULL-terminated array of ports that match the
   specified arguments.
   
   port_name_pattern: a regular expression used to select ports by name.
                      if NULL or of zero length, no selection based on
		      name will be carried out.

   type_name_pattern: a regular expression used to select ports by type.
                      if NULL or of zero length, no selection based on
		      type will be carried out.

   flags:             a value used to select ports by their flags.  if 
                      zero, no selection based on flags will be carried out.
*/

jack_port_t **jack_get_ports (jack_client_t *,
                              const char *port_name_pattern,
                              const char *type_name_pattern,
                              unsigned long flags);

/* If a client is told to become the timebase for the entire system,
   it calls this function. If it returns zero, then the client has
   the responsibility to call jack_update_time() at the end
   of its process() callback. Whatever time it provides (in frames
   since its reference zero time) becomes the current timebase
   for the entire system.
*/

int  jack_engine_takeover_timebase (jack_client_t *);
void jack_update_time (jack_client_t *, nframes_t);

/* useful access functions */

static __inline__ const char * jack_port_name (jack_port_t *port) { return port->shared->name; }

#ifdef __cplusplus
}
#endif

#endif /* __jack_h__ */

