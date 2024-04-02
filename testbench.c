/* SPDX-License-Identifier: Apache-2.0 */
/**       
 * @file        testbench.c
 *
 * @brief       Testbench code file for CXL State library
 *   
 * @copyright   Copyright (C) 2024 Jackrabbit Founders LLC. All rights reserved.
 *       
 * @date        Mar 2024
 * @author      Barrett Edwards <code@jrlabs.io>
 *          
 */

/* INCLUDES ==================================================================*/

#include <linux/types.h>

#include "cxlstate.h"

/* MACROS ====================================================================*/

/* ENUMERATIONS ==============================================================*/

/* STRUCTS ===================================================================*/

/* GLOBAL VARIABLES ==========================================================*/

/* PROTOTYPES ================================================================*/

int main()
{
	struct cxl_switch *s = cxls_init(32, 32, 256);

	cxls_prnt(s);
	
	cxls_free(s);

	return 0;
}
