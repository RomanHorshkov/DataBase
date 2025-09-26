
#pragma once
#include "db.h"

/* Grant presence-only ACL both directions (single Tx provided by caller). */
int acl_grant_tx(DB* db, Tx* tx, const uuid16_t* principal, u8 rtype,
                 const uuid16_t* resource);
