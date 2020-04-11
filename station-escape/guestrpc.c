/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

/** @file
 *
 * VMware GuestRPC mechanism
 *
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "backdoor.h"

/**
 * Open GuestRPC channel
 *
 * @ret channel		Channel number, or negative error
 */
int guestrpc_open ( void ) {
	uint16_t channel;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( 0, GUESTRPC_OPEN, GUESTRPC_MAGIC,
				       &channel, &discard_b );
	if ( status != GUESTRPC_OPEN_SUCCESS ) {
		printf( "GuestRPC open failed: status %08x\n",
		       status );
		return -1;
	}

	printf ( "GuestRPC channel %d opened\n", channel );
	return channel;
}

/**
 * Send GuestRPC command length
 *
 * @v channel		Channel number
 * @v len		Command length
 * @ret rc		Return status code
 */
static int guestrpc_command_len ( int channel, size_t len ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_COMMAND_LEN, len,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_COMMAND_LEN_SUCCESS ) {
		printf ( "GuestRPC channel %d send command "
		       "length %zd failed: status %08x\n",
		       channel, len, status );
		return -1;
	}

	return 0;
}

/**
 * Send GuestRPC command data
 *
 * @v channel		Channel number
 * @v data		Command data
 * @ret rc		Return status code
 */
static int guestrpc_command_data ( int channel, uint32_t data ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_COMMAND_DATA, data,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_COMMAND_DATA_SUCCESS ) {
		printf ( "GuestRPC channel %d send command "
		       "data %08x failed: status %08x\n",
		       channel, data, status );
		return -1;
	}

	return 0;
}

/**
 * Receive GuestRPC reply length
 *
 * @v channel		Channel number
 * @ret reply_id	Reply ID
 * @ret len		Reply length, or negative error
 */
static int guestrpc_reply_len ( int channel, uint16_t *reply_id ) {
	uint32_t len;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_REPLY_LEN, 0,
				       reply_id, &len );
	if ( status != GUESTRPC_REPLY_LEN_SUCCESS ) {
		printf ( "GuestRPC channel %d receive reply "
		       "length failed: status %08x\n", channel, status );
		return -1;
	}

	return len;
}

/**
 * Receive GuestRPC reply data
 *
 * @v channel		Channel number
 * @v reply_id		Reply ID
 * @ret data		Reply data
 * @ret rc		Return status code
 */
static int guestrpc_reply_data ( int channel, uint16_t reply_id,
				 uint32_t *data ) {
	uint16_t discard_d;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_REPLY_DATA, reply_id,
				       &discard_d, data );
	if ( status != GUESTRPC_REPLY_DATA_SUCCESS ) {
		printf ( "GuestRPC channel %d receive reply "
		       "%d data failed: status %08x\n",
		       channel, reply_id, status );
		return -1;
	}

	return 0;
}

/**
 * Finish receiving GuestRPC reply
 *
 * @v channel		Channel number
 * @v reply_id		Reply ID
 * @ret rc		Return status code
 */
static int guestrpc_reply_finish ( int channel, uint16_t reply_id ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_REPLY_FINISH, reply_id,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_REPLY_FINISH_SUCCESS ) {
		printf ( "GuestRPC channel %d finish reply %d "
		       "failed: status %08x\n", channel, reply_id, status );
		return -1;
	}

	return 0;
}

/**
 * Close GuestRPC channel
 *
 * @v channel		Channel number
 */
void guestrpc_close ( int channel ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_CLOSE, 0,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_CLOSE_SUCCESS ) {
		printf ( "GuestRPC channel %d close failed: "
		       "status %08x\n", channel, status );
		return;
	}

	printf ( "GuestRPC channel %d closed\n", channel );
}

/**
 * Issue GuestRPC command
 *
 * @v channel		Channel number
 * @v command		Command
 * @v reply		Reply buffer
 * @v reply_len		Length of reply buffer
 * @ret len		Length of reply, or negative error
 *
 * The actual length of the reply will be returned even if the buffer
 * was too small.
 */
int guestrpc_command ( int channel, const char *command, char *reply,
		       size_t reply_len ) {
	const uint8_t *command_bytes = ( ( const void * ) command );
	uint8_t *reply_bytes = ( ( void * ) reply );
	size_t command_len = strlen ( command );
	int orig_reply_len = reply_len;
	uint16_t status;
	uint8_t *status_bytes = ( ( void * ) &status );
	size_t status_len = sizeof ( status );
	uint32_t data;
	uint16_t reply_id;
	int len;
	int remaining;
	unsigned int i;
	int rc;

	printf ( "GuestRPC channel %d issuing command:\n",
		channel );

	/* Sanity check */
	assert ( ( reply != NULL ) || ( reply_len == 0 ) );

	/* Send command length */
	if ( ( rc = guestrpc_command_len ( channel, command_len ) ) < 0 )
		return rc;

	/* Send command data */
	while ( command_len ) {
		data = 0;
		for ( i = sizeof ( data ) ; i ; i-- ) {
			if ( command_len ) {
				data = ( ( data & ~0xff ) |
					 *(command_bytes++) );
				command_len--;
			}
			data = ( ( data << 24 ) | ( data >> 8 ) );
		}
		if ( ( rc = guestrpc_command_data ( channel, data ) ) < 0 )
			return rc;
	}

	/* Receive reply length */
	if ( ( len = guestrpc_reply_len ( channel, &reply_id ) ) < 0 ) {
		rc = len;
		return rc;
	}

	/* Receive reply */
	for ( remaining = len ; remaining > 0 ; remaining -= sizeof ( data ) ) {
		if ( ( rc = guestrpc_reply_data ( channel, reply_id,
						  &data ) ) < 0 ) {
			return rc;
		}
		for ( i = sizeof ( data ) ; i ; i-- ) {
			if ( status_len ) {
				*(status_bytes++) = ( data & 0xff );
				status_len--;
				len--;
			} else if ( reply_len ) {
				*(reply_bytes++) = ( data & 0xff );
				reply_len--;
			}
			data = ( ( data << 24 ) | ( data >> 8 ) );
		}
	}

	/* Finish receiving RPC reply */
	if ( ( rc = guestrpc_reply_finish ( channel, reply_id ) ) < 0 )
		return rc;

	printf ( "GuestRPC channel %d received reply (id %d, "
		"length %d):\n", channel, reply_id, len );

	/* Check reply status */
	if ( status != GUESTRPC_SUCCESS ) {
		printf ( "GuestRPC channel %d command failed "
		       "(status %04x, reply id %d, reply length %d):\n",
		       channel, status, reply_id, len );
		return -EIO;
	}

	return len;
}
