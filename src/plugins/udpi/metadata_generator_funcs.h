#ifndef UDPI_METADATA_PRODUCER_FUNCS_H
#define UDPI_METADATA_PRODUCER_FUNCS_H

#include "session.h"

u8 *
produce_v4_csv_record(const vlib_main_t* vm, const session_t *session, u8 *buffer);

u8 *
produce_v6_csv_record(const vlib_main_t* vm, const session_t *session, u8 *buffer);

#endif