#ifndef UDPI_SESSION_INLINES_H_
#define UDPI_SESSION_INLINES_H_

#include <vppinfra/clib.h>

#include "session.h"

static_always_inline __clib_unused session_direction_t
to_session_direction(const session_t *session, const flow_direction_t flow_direction)
{
	return (session_direction_t) (flow_direction == session->c2s_flow);
}

#endif