#ifndef UDPI_TCP_SESSION_H_
#define UDPI_TCP_SESSION_H_

#include <vlib/counter_types.h>
#include <vlib/vlib.h>

#include <vppinfra/mem.h>

#include "session.h"

#define TCP_QUEUE_SIZE	16

typedef enum
{
	TCP_HANDSHAKE_INIT,
	TCP_HANDSHAKE_SUCCESSFUl,
	TCP_HANDSHAKE_FAILED
} tcp_handshake_t;

typedef struct
{
	u32 seq_num;
	u32 ack_num;
	vlib_buffer_t *b;
} tcp_segment_t;

typedef struct
{
	u32 size;
	tcp_segment_t seg[TCP_QUEUE_SIZE];
} tcp_queue_t;

typedef struct
{
	u32 seq_num;
	u32 ack_num;
	tcp_queue_t queue;
} tcp_flow_t;

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
	u32 syn_seq_end;
	u32 syn_ack_seq_end;
	tcp_handshake_t handshake;
	tcp_flow_t flow[SESSION_DIRECTION_COUNT];
} tcp_session_t;


#endif