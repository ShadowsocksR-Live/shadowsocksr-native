/* -*- coding: utf-8 -*-
 * ----------------------------------------------------------------------
 * Copyright © 2012, RedJack, LLC.
 * All rights reserved.
 *
 * Please see the COPYING file in this distribution for license
 * details.
 * ----------------------------------------------------------------------
 */

#ifndef LIBCORK_CORE_API_H
#define LIBCORK_CORE_API_H

#include <libcork/core/attributes.h>

/* If you're using libcork as a shared library, you don't need to do anything
 * special; the following will automatically set things up so that libcork's
 * public symbols are imported from the library.  When we build the shared
 * library, we define this ourselves to export the symbols. */

#if !defined(CORK_API)
#define CORK_API  CORK_IMPORT
#endif

#endif /* LIBCORK_CORE_API_H */
