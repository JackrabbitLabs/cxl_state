/* SPDX-License-Identifier: Apache-2.0 */
/**       
 * @file        cxlstate.h
 *
 * @brief       Header file for CXL State library
 *   
 * @copyright   Copyright (C) 2024 Jackrabbit Founders LLC. All rights reserved.
 *       
 * @date        Mar 2024
 * @author      Barrett Edwards <code@jrlabs.io>
 *          
 */

#ifndef _CXLSTATE_H
#define _CXLSTATE_H

/* INCLUDES ==================================================================*/

/* pthread_mutex_t
 */
#include <pthread.h>

#include <linux/types.h>

/* MACROS ====================================================================*/

#define CXLN_LD 				16
#define CXLN_PORTS 				256
#define CXLN_VCSS 				256
#define CXLN_VPPBS_PER_VCS  	256
#define CXLN_VPPBS 				(CXLN_PORTS * CXLN_LD)
#define CXLN_DEVICES 			128
#define CXLN_MAX_INDENT 		32
#define CXLN_INDENT 			2
#define CXLN_CFG_SPACE      	4096
#define CXLN_FILE_NAME			256

/* ENUMERATIONS ==============================================================*/

/**
 * CXLS Verbosity Bit Field (VB)
 */
enum _CXVB
{
	CXVB_GENERAL	= (0x01 << 0),
	CXVB_CALLSTACK 	= (0x01 << 1),
	CXVB_STEPS		= (0x01 << 2)
};

/* STRUCTS ===================================================================*/

/**
 * Multi Logical Device Object*
 *
 * This device aggregates all the descriptors for a CXL MLD Logical Device 
 *
 * CXL 2.0 v1.0 Table 111,112,113,116,117,118,119
 */
struct cxl_mld 
{
	/* LD Info: Table 111*/
	__u64 memory_size; 				//!< Total device memory capacity
	__u16 num;						//!< Number of Logical Devices supported
	__u8 epc;						//!< Egress Port Congestion Supported 
	__u8 ttr;						//!< Temporary Throughput Reduction Supported 

	/* LD Allocations: Table 112,113 */
	__u8 granularity;				//!< Memory Granularity [FMMG]
	__u64 rng1[CXLN_LD]; 			//!< Range 1 Allocation Multiplier
	__u64 rng2[CXLN_LD];			//!< Range 2 Allocation Multiplier

	/* LD QoS Control parameters: Table 116*/
	__u8 epc_en; 					//!< QoS Telem: Egress Port Congestion Enable. Bitfield [FMQT]
	__u8 ttr_en; 					//!< QoS Telem: Temporary Throuhput Reduction Enable. Bitfield [FMQT]
	__u8 egress_mod_pcnt;			//!< Egress Moderate Percentage: Valid range 1-100. Default 10
	__u8 egress_sev_pcnt;			//!< Egress Severe Percentage: Valid range 1-100. Default 25
	__u8 sample_interval;			//!< Backpressure Sample Interval: Valid range is 0-15. Default 8 (800 ns of history). 0 disables 
	__u16 rcb;						//!< ReqCmpBasis. Valid range is 0-65,535. 0 disables. Default 0.
	__u8 comp_interval;				//!< Completion Collection Interval: Valid range 0-255. Default 64

	/* LD QoS Status: Table 117*/
	__u8 bp_avg_pcnt;				//!< Backpressure Average Percentage 

	/* LD QoS Allocated BW Fractions: Table 118 */
	__u8 alloc_bw[CXLN_LD];

	/* LD QoS BW Limit Fractions: Table 119 */
	__u8 bw_limit[CXLN_LD];

	__u8 *cfgspace[CXLN_LD];		//!< Buffers representing PCIe config space for each logical device

	__u8 mmap;						//!< Direction to mmap a file for the memory space
	char *file;						//!< Filename for mmaped file 
	__u8 *memspace;					//!< Buffer representing memory space for entire logical device
};

/**
 * Virtual PCIe-to-PCIe Bridge Object 
 *
 * CXL 2.0 v1.0 Table 99
 */
struct cxl_vppb 
{
	__u16 vppbid;					//!< Index of this vPPB in the state->vppbs[] array
	__u8 bind_status;				//!< PBB Binding Status [FMBS]
	__u8 ppid;						//!< Physical port number of bound port
	__u16 ldid;						//!< ID of LD bound to port from MLD on associated physical port
};

/**
 * Virtual CXL Switch Object
 * 
 * CXL 2.0 v1.0 Table 99
 */
struct cxl_vcs 
{
	__u8 vcsid;						//!< VCS ID - Index of this vcs in the state->vcss[] array
	__u8 state; 					//!< Virtual CXL switch State [FMVS]
	__u8 uspid; 					//!< USP Physical Port ID
	__u8 num;						//!< Number of vPPBs
	
	//!< Array of pointers to vPPB objects
	struct cxl_vppb vppbs[CXLN_VPPBS_PER_VCS];	
};

/**
 * CXL Switch Port Object
 *
 * CXL 2.0 v1.0 Table 92
 */
struct cxl_port 
{
	__u8 ppid;						//!< Port ID - Index of this port in the state->ports[] array
	__u8 state;						//!< Current Port Configuration State [FMPS]
    __u8 dv;						//!< Connected Device CXL version [FMDV]
    __u8 dt;						//!< Connected device type [FMDT]
    __u8 cv;						//!< Connected CXL version bitmask [FMVC]
    __u8 mlw;						//!< Max Link Width. Integer number of lanes (1,2,4,8,16)
    __u8 nlw;						//!< Negotiated Link Width [FMNW]
    __u8 speeds;					//!< Supported Link Speeds Vector [FMSS]
    __u8 mls;						//!< Maximum Link Speed [FMMS]
    __u8 cls;						//!< Current Link Speed [FMMS]
    __u8 ltssm;						//!< LTSSM State [FMLS]
	__u8 lane;						//!< First negotiated lane number (Integer lane number)

    /** Link State Flags [FMLF] [FMLO] */ 
	__u8 lane_rev; 					//!< Lane reversal state. 0=standard, 1=rev [FMLO]
	__u8 perst;						//!< PCIe Reset State PERST#	
	__u8 prsnt;						//!< Port Presence pin state PRSNT#
	__u8 pwrctrl;					//!< Power Control State (PWR_CTRL)
	
    __u8 ld;						//!< Additional supported LD Count (beyond 1)
	__u8 *cfgspace;					//!< Buffer representing PCIe config space
	struct cxl_mld *mld;			//!< State for MLD
	char *device_name;				//!< Name of device used to populate this port
};

/**
 * CXL Device Profile
 */
struct cxl_device 
{
	char *name;						//!< Name of device 
	__u8 rootport;					//!< Root Port Device. 1=root, 2=endpoint
    __u8 dv;						//!< Connected Device CXL version [FMDV]
    __u8 dt;						//!< Connected device type [FMDT]
    __u8 cv;						//!< Connected CXL version bitmask [FMVC]
    __u8 mlw;						//!< Maximum Link Width. Integer number of lanes (1,2,4,8,16)
    __u8 mls;						//!< Maximum Link Speed [FMMS]
	__u8 *cfgspace;					//!< Buffer representing PCIe config space
	struct cxl_mld *mld;			//!< MLD info if this is an MLD
};

/**
 * CXL Switch State Identify Information
 *
 * CXL 2.0 v1 Table 89
 */
struct cxl_switch
{ 
	__u8 version; 				//!< Device Management Version

	__u16 vid; 					//!< PCIe Vendor ID 
	__u16 did; 					//!< PCIe Device ID 
	__u16 svid;					//!< PCIe Subsystem Vendor ID 
	__u16 ssid; 				//!< PCIe Subsystem ID 
	__u64 sn; 					//!< Device Serial Number
	__u8 max_msg_size_n;		//!< Max fmapi msg size. 2^n

	__u8 msg_rsp_limit_n;		//!< Message Response Limit n of 2^n

	__u8 bos_running;			//!< Background operation status 0=none, 1=running
	__u8 bos_pcnt;				//!< Background operation percent complete [0-100]
	__u16 bos_opcode;			//!< Background operation opcode
	__u16 bos_rc;				//!< Background operation return code
	__u16 bos_ext;				//!< Background operation Extended Vendor Status 

	__u8 ingress_port;			//!< Ingress Port ID 
	__u8 num_ports;				//!< Total number of physical ports
	__u8 num_vcss; 				//!< Max number of VCSs
	__u16 num_vppbs;			//!< Max number of vPPBs 
	__u16 active_vppbs;			//!< Number of active vPPBs
	__u8 num_decoders;			//!< Number of HDM decoders available per USP 

	struct cxl_port *ports;		//!< array of Port objects
	struct cxl_vcs *vcss;		//!< array of VCS objects

	struct cxl_device *devices; //!< array of device definitions 
	__u16 len_devices;			//!< Number of entries supported in devices array
	__u16 num_devices;			//!< Number of entries in devices array

	/* Port defaults */
    __u8 mlw;					//!< Max Link Width. Integer number of lanes (1,2,4,8,16)
    __u8 speeds;				//!< Supported Link Speeds Vector [FMSS]
    __u8 mls;					//!< Maximum Link Speed [FMMS]
	char *dir;					//!< Filepath to directory for instantiated memory
	
	pthread_mutex_t mtx;	//!< Mutex to control access to this object
};


/* GLOBAL VARIABLES ==========================================================*/

extern __u64 cxls_verbosity;

/* PROTOTYPES ================================================================*/

struct cxl_switch *cxls_init(unsigned ports, unsigned vcss, unsigned vppbs);
void cxls_free 			(struct cxl_switch *s);

int cxls_connect 	(struct cxl_port *p, struct cxl_device *d, char *dir);
int cxls_disconnect (struct cxl_port *p);

void cxls_prnt 			(struct cxl_switch *s);
void cxls_prnt_identity	(struct cxl_switch *s, 	unsigned indent);
void cxls_prnt_devices 	(struct cxl_switch *s);
void cxls_prnt_ports	(struct cxl_switch *s, 	unsigned indent);
void cxls_prnt_port		(struct cxl_port *p, 	unsigned indent);
void cxls_prnt_vcss		(struct cxl_switch *s, 	unsigned indent);
void cxls_prnt_vcs		(struct cxl_vcs *v, 	unsigned indent);
void cxls_prnt_vppb		(struct cxl_vppb *b, 	unsigned indent);
void cxls_prnt_mld		(struct cxl_mld *m, 	unsigned indent);

#endif /* ifndef _CXLSTATE_H */
