#ifndef UDPI_METADATA_PRODUCER_FUNCS_H
#define UDPI_METADATA_PRODUCER_FUNCS_H

#include "ip_session.h"

u8 *
produce_v4_csv_record(u8 *buffer, ipv4_session_t *session);

u8 *
produce_v6_csv_record(u8 *buffer, ipv6_session_t *session);

#endif