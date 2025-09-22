/**
 * @file utils.h
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_UTILS_H
#define DB_UTILS_H

#include "fsutil.h"
#include "time.h"
#include "uuid.h"

inline uint64_t now_secs(void)
{
    return (uint64_t)time(NULL);
}

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
 */

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
 */

#ifdef __cplusplus
}
#endif

#endif /* DB_INTERNAL_H */
