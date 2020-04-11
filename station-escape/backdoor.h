#ifndef _IPXE_VMWARE_H
#define _IPXE_VMWARE_H

/** @file
 *
 * VMware backdoor mechanism
 *
 */

#include <stdint.h>

/** VMware backdoor I/O port */
#define VMW_PORT 0x5658

/** VMware backdoor magic value */
#define VMW_MAGIC 0x564d5868 /* "VMXh" */
#define GUESTRPC_MAGIC 0x49435052 /* "RPCI" */

/** VMware backdoor magic instruction */
#define VMW_BACKDOOR "inl %%dx, %%eax"

/** Get VMware version */
#define VMW_CMD_GET_VERSION 0x0a

/** Issue GuestRPC command */
#define VMW_CMD_GUESTRPC 0x1e

/** ------------------------------------------------------ **/

/** Open RPC channel */
#define GUESTRPC_OPEN 0x00

/** Open RPC channel success status */
#define GUESTRPC_OPEN_SUCCESS 0x00010000

/** Send RPC command length */
#define GUESTRPC_COMMAND_LEN 0x01

/** Send RPC command length success status */
#define GUESTRPC_COMMAND_LEN_SUCCESS 0x00810000

/** Send RPC command data */
#define GUESTRPC_COMMAND_DATA 0x02

/** Send RPC command data success status */
#define GUESTRPC_COMMAND_DATA_SUCCESS 0x00010000

/** Receive RPC reply length */
#define GUESTRPC_REPLY_LEN 0x03

/** Receive RPC reply length success status */
#define GUESTRPC_REPLY_LEN_SUCCESS 0x00830000

/** Receive RPC reply data */
#define GUESTRPC_REPLY_DATA 0x04

/** Receive RPC reply data success status */
#define GUESTRPC_REPLY_DATA_SUCCESS 0x00010000

/** Finish receiving RPC reply */
#define GUESTRPC_REPLY_FINISH 0x05

/** Finish receiving RPC reply success status */
#define GUESTRPC_REPLY_FINISH_SUCCESS 0x00010000

/** Close RPC channel */
#define GUESTRPC_CLOSE 0x06

/** Close RPC channel success status */
#define GUESTRPC_CLOSE_SUCCESS 0x00010000

/** RPC command success status */
#define GUESTRPC_SUCCESS 0x2031 /* "1 " */

/** ------------------------------------------------------ **/

/**
 * Get VMware version
 *
 * @ret version		VMware version(?)
 * @ret magic		VMware magic number, if present
 * @ret product_type	VMware product type
 */
static inline __attribute__ (( always_inline )) void
vmware_cmd_get_version ( uint32_t *version, uint32_t *magic,
			 uint32_t *product_type ) {
	uint32_t discard_d;

	/* Perform backdoor call */
	__asm__ __volatile__ ( VMW_BACKDOOR
			       : "=a" ( *version ), "=b" ( *magic ),
				 "=c" ( *product_type ), "=d" ( discard_d )
			       : "0" ( VMW_MAGIC ), "1" ( 0 ),
				 "2" ( VMW_CMD_GET_VERSION ),
				 "3" ( VMW_PORT ) );
}

/**
 * Issue GuestRPC command
 *
 * @v channel		Channel number
 * @v subcommand	GuestRPC subcommand
 * @v parameter		Subcommand-specific parameter
 * @ret edxhi		Subcommand-specific result
 * @ret ebx		Subcommand-specific result
 * @ret status		Command status
 */
static inline __attribute__ (( always_inline )) uint32_t
vmware_cmd_guestrpc ( int channel, uint16_t subcommand, uint32_t parameter,
		      uint16_t *edxhi, uint32_t *ebx ) {
	uint32_t discard_a;
	uint32_t status;
	uint32_t edx;

	/* Perform backdoor call */
	__asm__ __volatile__ ( VMW_BACKDOOR
			       : "=a" ( discard_a ), "=b" ( *ebx ),
				 "=c" ( status ), "=d" ( edx )
			       : "0" ( VMW_MAGIC ), "1" ( parameter ),
				 "2" ( VMW_CMD_GUESTRPC | ( subcommand << 16 )),
				 "3" ( VMW_PORT | ( channel << 16 ) ) );
	*edxhi = ( edx >> 16 );

	return status;
}

extern int vmware_present ( void );

#endif /* _IPXE_VMWARE_H */
