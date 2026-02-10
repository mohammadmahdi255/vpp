#ifndef L2TP_DETUNNEL_H_
#define L2TP_DETUNNEL_H_

#include <arpa/inet.h>

#include "detunnel_result.h"
#include "vnet/ethernet/packet.h"
#include "vppinfra/byte_order.h"

typedef struct
{
	uint8_t priority:1;
	uint8_t offset_bit_present:1;
	uint8_t reserve2:1;
	uint8_t sequence_bit_present:1;
	uint8_t reserve:2;
	uint8_t length_bit_present:1;
	uint8_t type:1;

	uint8_t version:4;
	uint8_t reserve3:4;
} l2tp_header_t;

#define DATA_MESSAGE_TYPE		0
#define LENGTH_FIELD_SIZE		2
#define SEQUENCE_FIELD_SIZE		4
#define TUNNEL_ID_FIELD_SIZE	2
#define SESSION_ID_FIELD_SIZE	2
#define OFFSET_SIZE_FIELD_SIZE	2
#define L2TP_SUPPORTED_VERSION	2

always_inline detunnel_result_t l2tp_detunnel(vlib_buffer_t* buffer)
{
	detunnel_result_t result = {DETUNNEL_STATUS_SUCCESSFUL, 0, 0};

	if (PREDICT_FALSE(buffer->current_length < sizeof(l2tp_header_t)))
	{
		clib_warning("Not enough bytes to read L2TP header");
		result.status = DETUNNEL_STATUS_INSUFFICIENT_SIZE;
		return result;
	}

	l2tp_header_t* l2tp_header = vlib_buffer_get_current(buffer);

	if (PREDICT_FALSE(l2tp_header->version != L2TP_SUPPORTED_VERSION))
	{
		clib_warning("Packet is not L2TP");
		result.status = DETUNNEL_STATUS_WRONG_FIELD;
		return result;
	}

	switch (l2tp_header->type)
	{
		case DATA_MESSAGE_TYPE:
		{
			u16 header_size = (u16) sizeof(l2tp_header_t)
					+ (l2tp_header->length_bit_present) * LENGTH_FIELD_SIZE
					+ TUNNEL_ID_FIELD_SIZE + SESSION_ID_FIELD_SIZE
					+ (l2tp_header->sequence_bit_present) * SEQUENCE_FIELD_SIZE;

			u16 offset_size = ntohs(*(u16*)(vlib_buffer_get_current(buffer) + header_size));

			header_size += (l2tp_header->offset_bit_present) * (OFFSET_SIZE_FIELD_SIZE + offset_size);

			result.next_protocol = ETHERNET_TYPE_PPP;
			result.processed_bytes = header_size;
			break;
		}
		default:
		{
			result.processed_bytes = buffer->current_length;
			break;
		}
	}

	vlib_buffer_advance(buffer, result.processed_bytes);
	result.status = DETUNNEL_STATUS_SUCCESSFUL;

	return result;
}

#endif