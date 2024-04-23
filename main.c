/* SPDX-License-Identifier: Apache-2.0 */
/**       
 * @file        cxlstate.c
 *
 * @brief       Code file for CXL State library
 *   
 * @copyright   Copyright (C) 2024 Jackrabbit Founders LLC. All rights reserved.
 *       
 * @date        Mar 2024
 * @author      Barrett Edwards <code@jrlabs.io>
 *          
 */

/* INCLUDES ==================================================================*/

/* gettid()
 */
#define _GNU_SOURCE

#include <unistd.h>

/* printf()
 */
#include <stdio.h>

/* malloc()
 * free()
 */
#include <stdlib.h>

/* errno
 */
#include <errno.h>

/* pthread_mutex_t
 */
#include <pthread.h>

/* memset()
 */
#include <string.h>

/* mmap()
 */
#include <sys/mman.h>

/* 
 */
#include <linux/types.h>

/* fmdt()
 * fmdv()
 * fmvc()
 */
#include <fmapi.h>

#include <arrayutils.h>

/* pcie_prnt_cfgspace()
 */
#include <pciutils.h>

#include "main.h"

/* MACROS ====================================================================*/

#ifdef CXLS_VERBOSE
 #define INIT 			unsigned step = 0;
 #define ENTER 					if (cxls_verbosity & CXVB_CALLSTACK) 	printf("%d:%s Enter\n", 			gettid(), __FUNCTION__);
 #define STEP 			step++; if (cxls_verbosity & CXVB_STEPS) 		printf("%d:%s STEP: %u\n", 			gettid(), __FUNCTION__, step);
 #define HEX32(m, i)			if (cxls_verbosity & CXVB_STEPS) 		printf("%d:%s STEP: %u %s: 0x%x\n",	gettid(), __FUNCTION__, step, m, i);
 #define INT32(m, i)			if (cxls_verbosity & CXVB_STEPS) 		printf("%d:%s STEP: %u %s: %d\n",	gettid(), __FUNCTION__, step, m, i);
 #define EXIT(rc) 				if (cxls_verbosity & CXVB_CALLSTACK) 	printf("%d:%s Exit: %d\n", 			gettid(), __FUNCTION__,rc);
#else
 #define INIT 
 #define ENTER
 #define STEP
 #define HEX32(m, i)
 #define INT32(m, i)
 #define EXIT(rc)
#endif // CSE_VERBOSE

#define IFV(u) 					if (cxls_verbosity & u) 

/* ENUMERATIONS ==============================================================*/

/* STRUCTS ===================================================================*/

/* PROTOTYPES ================================================================*/

void cxls_free_ports(struct cxl_switch *s);
void cxls_free_vcss(struct cxl_switch *s);

/* GLOBAL VARIABLES ==========================================================*/

__u64 cxls_verbosity = 0;

/* FUNCTIONS =================================================================*/

/**
 * Copy data from a device definition to a port 
 *
 * @param p 	struct cxl_port* to fill with data
 * @param d 	struct cxl_device* to pull the data from
 * @param dir 	char* for the directory name for mmaped files
 * 
 * STEPS:
 * 1: Copy basic parameters 
 * 2: Copy PCIe config space to the port
 * 3: Copy MLD information if present 
 * 4: Memory Map a file if requested by the device profile 
 */
int cxls_connect(struct cxl_port *p, struct cxl_device *d, char *dir)
{
	INIT 
	int rv;
	unsigned i;
	char filename[CXLN_FILE_NAME];
	FILE *fp;

	ENTER

	// Initialize variables
	rv = 1;

	// Validate Inputs 
	if (d->name == NULL)
		goto end;

	STEP // 1: Copy basic parameters 
    p->dv = d->dv;			
    p->dt = d->dt;			
    p->cv = d->cv;			
	p->ltssm = FMLS_L0;
	p->lane = 0;
	p->lane_rev = 0;
	p->perst = 0;
	p->pwrctrl = 0;
	p->ld = 0;

	// If the device definition says this is a rootport then set as an Upstream Port
	if( d->rootport == 1 )
		p->state = FMPS_USP;
	else 
		p->state = FMPS_DSP;

	// Pick the lower of the two widths
	if (d->mlw < p->mlw)
    	p->nlw = d->mlw;
	else 
		p->nlw = p->mlw;

	// Pick the lower of the two speeds
	if (d->mls < p->mls)
		p->cls = d->mls;
	else 
		p->cls = p->mls;

	// Set present bit 
 	p->prsnt = 1; 

	STEP // 2: Copy PCIe config space to the port
	memcpy(p->cfgspace, d->cfgspace, CXLN_CFG_SPACE);

	STEP // 3: Copy MLD information if present 
	if (d->mld != NULL) 
	{
    	p->ld = d->mld->num;

		// Allocate memory for MLD object in the port
		p->mld = malloc(sizeof(struct cxl_mld));

		// Copy MLD from device definition to port 
		memcpy(p->mld, d->mld, sizeof(struct cxl_mld));

		for ( i = 0 ; i < d->mld->num ; i++ )
		{
			// Allocate memory for each LD pcie config space
			p->mld->cfgspace[i] = malloc(CXLN_CFG_SPACE);
			
			// Copy PCIe config space from device definition to port
			memcpy(p->mld->cfgspace[i], d->cfgspace, CXLN_CFG_SPACE);
		}
	}

	STEP // 4: Memory Map a file if requested by the device profile 
	if (d->mld != NULL && d->mld->mmap == 1) 
	{
		// Prepare filename
		sprintf(filename, "%s/port%02d", dir, p->ppid);

		// Create file
		fp = fopen(filename, "w+");
		if (fp == NULL) {
			printf("Error: Could not open file: %s\n", filename);
			goto end;
		}

		// Truncate file to desired length
		rv = ftruncate(fileno(fp), p->mld->memory_size);
		if (rv != 0) {
			printf("Error: Could not truncate file. Memory Size: 0x%llx errno: %d\n", p->mld->memory_size, errno);
			goto end;
		}

		// mmap file
		p->mld->memspace = mmap(NULL, p->mld->memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(fp), 0);
		if (p->mld->memspace == NULL) {
			printf("Error: Could not mmap the file. errno: %d\n", errno);
			rv = 1;
			goto end;
		}

		// Save the filename to the port mld object 
		p->mld->file = strdup(filename);

		// Close file 
		fclose(fp);
	
	}

	rv = 0;

end:

	return rv;
}

/**
 * Clear / Free data from a port device definition 
 *
 * This function essemtially makes it appear as if the device has been removed from the slot
 *
 * @param p	struct cxl_port* The port to clear of values
 *
 * STEPS:
 * 1: Clear basic parameters 
 * 2: Clear PCIe config space 
 * 3: Free device name 
 * 4: Unmemmap MLD if present 
 * 5: Free PCIe cfg space for each ld
 * 6: Free MLD if present
 */
int cxls_disconnect(struct cxl_port *p)
{
	INIT
	int rv;
	unsigned i;

	ENTER 

	// Initialize variables
	rv = 1;

	STEP // 1: Clear basic parameters 
    p->dv = 0;
    p->dt = 0;			
    p->cv = 0;			
    p->nlw = 0;
	p->cls = 0;
	p->ltssm = 0;
	p->lane = 0;
	p->lane_rev = 0;
	p->perst = 0; 
 	p->prsnt = 0;
	p->pwrctrl = 0;
	p->ld = 0;

	STEP // 2: Clear PCIe config space 
	memset(p->cfgspace, 0, CXLN_CFG_SPACE);

	STEP // 3: Free device name 
	if (p->device_name != NULL) 
	{
		free(p->device_name);
		p->device_name = NULL;
	}

	STEP // 4: Unmemmap MLD if present 
	if (p->mld != NULL && p->mld->memspace != NULL)
	{
		msync (p->mld->memspace, p->mld->memory_size, MS_SYNC); 
		munmap(p->mld->memspace, p->mld->memory_size);
		p->mld->memspace = NULL;
	}

	STEP // 5: Free PCIe cfg space for each ld
	if (p->mld != NULL) 
	{
		for ( i = 0 ; i < p->mld->num ; i++ ) {
			if ( p->mld->cfgspace[i] != NULL ) {
				free(p->mld->cfgspace[i]);
				p->mld->cfgspace[i] = NULL;
			}
		}
	}

	STEP // 6: Free MLD if present
	if (p->mld != NULL) 
	{
		free(p->mld);
		p->mld = NULL;
	}

	rv = 0;

	return rv;
}

/**
 * Initialize state object with default values 
 * 
 * @return 	struct state. Returns 0 upon error and sets errno
 *
 * STEPS
 * 1: Validate inputs
 * 2: Initalize State Identity
 * 3: Initalize Ports 
 * 4: Initalize VCSs
 * 5: Initalize PCIe config space register
 */
struct cxl_switch *cxls_init(unsigned ports, unsigned vcss, unsigned vppbs)
{
	int rv;
	struct cxl_switch *s;

	rv = 0;

	// 1: Validate inputs
	if (ports > CXLN_PORTS)
		ports = CXLN_PORTS;
	if (vcss > CXLN_VCSS)
		vcss = CXLN_VCSS;
	if (vppbs > CXLN_VPPBS)
		vppbs = CXLN_VPPBS;

	// 2: Initalize State Identity
	s = calloc(1, sizeof(struct cxl_switch));
	if ( s == NULL ) 
	{
		errno = ENOMEM;
		goto end; 
	}
	
	// Initialize Identity information
	s->version = 1;
	s->vid = 0xb1b2;
	s->did = 0xc1c2;
	s->svid = 0xd1d2;
	s->ssid = 0xe1e2;
	s->sn = 0xa1a2a3a4a5a6a7a8;
	s->ingress_port = 1;
	s->num_decoders = 42;

	// Initialize Mutex
	pthread_mutex_init(&s->mtx, NULL);

	// 3: Initalize Ports 
	rv = cxls_init_ports(s, ports);
	if ( rv != 0 ) 
		goto end_state; 

	// 4: Initalize VCSs
	rv = cxls_init_vcss(s, vcss, vppbs / vcss);
	if ( rv != 0 ) 
		goto end_ports; 

	goto end;

end_ports:

	free(s->ports);
	s->ports = NULL;

end_state:

	free(s);
	s = NULL;

end:

	return s;
}

int cxls_init_ports(struct cxl_switch *s, unsigned ports)
{
	unsigned i;
	int rv;
	struct cxl_port *p;

	// Initialize variables 
	rv = 1;

	// Free existing array if present
	cxls_free_ports(s);

	// Allocate memory for new array 
	s->ports = calloc(ports, sizeof(struct cxl_port));
	if ( s->ports == NULL ) 
	{
		errno = ENOMEM;
		goto end; 
	}

	// Set default port values
	for ( i = 0 ; i < ports ; i++ ) 
	{
		p 				= &s->ports[i];
		p->ppid 		= i;
		p->state 		= FMPS_DISABLED;
   		p->dv 			= FMDV_NOT_CXL;
   		p->dt 			= FMDT_NONE;
   		p->cv 			= 0;
   		p->mlw 			= 16;
   		p->nlw 			= 0;
   		p->speeds 		= FMSS_PCIE5 | FMSS_PCIE4 | FMSS_PCIE3 | FMSS_PCIE2 | FMSS_PCIE1;
   		p->mls 			= FMMS_PCIE5;
   		p->cls 			= 0;
   		p->ltssm 		= FMLS_DISABLED;
   		p->lane 		= 0;
		p->lane_rev 	= 0;
		p->perst 		= 0;
		p->prsnt 		= 0;
		p->pwrctrl 		= 0;
   		p->ld 			= 0;
		p->cfgspace 	= calloc(1, CXLN_CFG_SPACE);

		if ( p->cfgspace == NULL )
		{
			errno = ENOMEM;
			goto end_cfgspace; 
		}
	}
	s->num_ports = ports;

	rv = 0;

	goto end;

end_cfgspace:
	
	cxls_free_ports(s);

end:

	return rv;
}

int cxls_init_vcss(struct cxl_switch *s, unsigned vcss, unsigned vppbs)
{
	unsigned i;
	int rv; 
	struct cxl_vcs *v;

	rv = 1;

	// Free existing array if present
	cxls_free_vcss(s);

	// Allocate memory for new array
	s->vcss = calloc(vcss, sizeof(struct cxl_vcs));
	if ( s->vcss == NULL ) 
	{
		errno = ENOMEM;
		goto end; 
	}

	// Set default vcs values
	for ( i = 0 ; i < vcss ; i++) 
	{
		v 			= &s->vcss[i];
		v->vcsid	= i;
		v->state	= FMVS_DISABLED;
		v->uspid	= 0;
		v->num		= vppbs / vcss;

		// Allocate and zero memory for vppb array 
		v->vppbs = calloc(v->num, sizeof(struct cxl_vppb));
		
		// Set the default status and vppbid in each vppb entry in this vcs 
		for ( int k = 0 ; k < v->num ; k++ )
		{
			v->vppbs[k].vppbid = k;
			v->vppbs[k].bind_status = FMBS_UNBOUND;
		}
	}
	s->num_vcss = vcss;
	s->num_vppbs = vppbs;

	rv = 0;

end:

	return rv;
}

/**
 * Free memory allocated by the CXL Switch State  
 * 
 * STEPS:
 * 1: Destroy Mutex
 * 2: Free pci config space memory 
 * 3: Free Port MLD config space
 * 4: unmap memory space if present 
 * 5: Free Port MLD
 * 6: Free VCSs
 * 7: Free ports
 * 8: Free devices
 * 9: Free Switch State
 */ 
void cxls_free(struct cxl_switch *s)
{
	unsigned i;
	
	struct cxl_device *d;
	
	if (s == NULL) 
		return;
	
	// 1: Destroy mutex
	pthread_mutex_destroy(&s->mtx);

	cxls_free_ports(s);

	// 6: Free VCSs & vppbs 
	cxls_free_vcss(s);

	// 8: Free devices
	if ( s->devices != NULL ) 
	{
		for ( i = 0 ; i < s->len_devices ; i++ )
		{
			d = &s->devices[i];

			// Free device name string if present 
			if ( d->name != NULL ) 
			{
				free(d->name);
				d->name = NULL;
			}

			// Free device pcie config space if present 
			if ( d->cfgspace != NULL ) 
			{
				free(d->cfgspace);
				d->cfgspace = NULL;
			}

			// Free device MLD if present 
			if ( d->mld != NULL) 
			{
				free(d->mld);
				d->mld = NULL;
			}
		}

		free(s->devices);
		s->devices = NULL;
	}
	s->len_devices = 0;
	s->num_devices = 0;

	// 9: Free Switch State
	if ( s->dir != NULL )
	{
		free(s->dir);
		s->dir = NULL;
	}

	if (s->pacc != NULL)
		pci_cleanup(s->pacc);

	free(s);
	s = NULL;
}

void cxls_free_ports(struct cxl_switch *s)
{
	unsigned i, k;
	struct cxl_port *p;

	if (s->ports == NULL)
		return;

	// 2: Free pci config space memory 
	for ( i = 0 ; i < s->num_ports ; i++ ) 
	{
		p = &s->ports[i];
		if ( p->cfgspace != NULL ) 
		{
			free(p->cfgspace);
			p->cfgspace = NULL;
		}
	}

	// 3: Free Port MLD config space
	for ( i = 0 ; i < s->num_ports ; i++ ) 
	{
		p = &s->ports[i];
		if ( p->mld != NULL ) 
		{
			for ( k = 0 ; k < CXLN_LD ; k++ ) 
			{
				if ( p->mld->cfgspace[k] != NULL )
				{
					free(p->mld->cfgspace[k]);
					p->mld->cfgspace[k] = NULL;
				}
			}
		}
	}

	// 4: unmap memory space if present 
	for ( i = 0 ; i < s->num_ports ; i++ ) 
	{
		p = &s->ports[i];
		if ( p->mld != NULL ) 
		{
			if ( p->mld->memspace != NULL ) 
			{
				munmap(p->mld->memspace, p->mld->memory_size);
				p->mld->memspace = NULL;
			}

			if ( p->mld->file != NULL ) 
			{
				free(p->mld->file);
				p->mld->file = NULL;
			}
		}
	}
	
	// 5: Free Port MLD
	for ( i = 0 ; i < s->num_ports ; i++ )
	{
		p = &s->ports[i];
		if ( p->mld != NULL )
		{
			free(p->mld);
			p->mld = NULL;
		}
	}

	// 7: Free Ports
	if ( s->ports != NULL ) 
	{
		free(s->ports);
		s->ports = NULL;
		s->num_ports = 0;
	}
}

void cxls_free_vcss(struct cxl_switch *s)
{
	unsigned i;

	if ( s->vcss != NULL )  
	{
		for ( i = 0 ; i < s->num_vcss ; i++)
			if (s->vcss[i].vppbs != NULL)
				free(s->vcss[i].vppbs);
		free(s->vcss);
		s->vcss = NULL;
		s->num_vcss = 0;
	}
}

/**
 * Print the CXL Switch State 
 */ 
void cxls_prnt(struct cxl_switch *s)
{
	cxls_prnt_identity(s, 0);
	cxls_prnt_ports(s, 0);
	cxls_prnt_vcss(s, 0);
}

/**
 * Print the Device List
 */ 
void cxls_prnt_devices(struct cxl_switch *s)
{
	unsigned i;
	struct cxl_device *d;

	if (s->devices == NULL) 
		return;
	
	for ( i = 0 ; i < s->num_devices ; i++ )
	{
		d = &s->devices[i];

		printf("%s:\n",       d->name);
		printf("  Port:\n"); 	
		printf("    dt:     %2d - %s\n", d->dt, fmdt(d->dt));
		printf("    dv:     %2d - %s\n", d->dv, fmdv(d->dv));
		printf("    cv:     %2d - %s\n", d->cv, fmvc(d->cv));
		printf("    mlw:    %2d\n",      d->mlw);
		
		pcie_prnt_cfgspace(d->cfgspace, 2);
	}
}

/**
 * Print the CXL Switch Idenfity Information
 *
 * @param	struct cxl_switch_state* to print
 * @param 	indent The number of spaces to indent the printed text
 */
void cxls_prnt_identity(struct cxl_switch *s, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	// Print fields
	printf("%singress_port: %u\n", 		space, s->ingress_port);
	printf("%snum_ports:    %u\n", 		space, s->num_ports);
	printf("%snum_vcss:     %u\n", 		space, s->num_vcss);
	printf("%snum_vppbs:    %u\n", 		space, s->num_vppbs);
	printf("%snum_decoders: %u\n", 		space, s->num_decoders);
	printf("%sdir:          %s\n", 		space, s->dir);

}

/**
 * Print CXL MLD Info
 *
 * @param 	mld		struct mld* to use to print
 * @param	indent 	The number of spaces to indent the printed text
 */
void cxls_prnt_mld(struct cxl_mld *m, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";
	int i;

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	printf("%sMulti-Logical Device:\n", space);

	space[indent] = ' ';
	space[indent+2] = 0;

	printf("%sMemory Size                               0x%016llx\n", 	space, m->memory_size);
	printf("%sNum LD                                    %d\n", 			space, m->num);
	printf("%sEgress Port Congestion Supported          %d\n", 			space, m->epc);
	printf("%sTemporary Throughput Reduction Supported  %d\n", 			space, m->ttr);
	printf("%sGranularity                               %d - %s\n", 	space, m->granularity, fmmg(m->granularity));
	printf("%sEgress Port Congestion Enabled            %d\n", 			space, m->epc_en);
	printf("%sTemporary Throughput Reduction Enabled    %d\n", 			space, m->ttr_en);
	printf("%sEgress Moderate Percentage                %d\n", 			space, m->egress_mod_pcnt);
	printf("%sEgress Severe Percentage                  %d\n", 			space, m->egress_sev_pcnt);
	printf("%sBackpressure Sample Interval              %d\n", 			space, m->sample_interval);
	printf("%sReqCmpBasis                               %d\n", 			space, m->rcb);
	printf("%sCompletion Collection Interval            %d\n", 			space, m->comp_interval);
	printf("%sBackpressure Average Percentage           %d\n", 			space, m->bp_avg_pcnt);
	printf("%smmap                                      %d\n", 			space, m->mmap);
	printf("%smmap file                                 %s\n", 			space, m->file);
	printf("\n");
	printf("%sLDID  Range 1            Range 2            Alloc BW BW Limit\n", space);
	printf("%s----  ------------------ ------------------ -------- --------\n", space);
	for ( i = 0 ; i < m->num ; i++ ) 
		printf("%s%4d: 0x%016llx 0x%016llx %8d %8d\n", space, i, m->rng1[i], m->rng2[i], m->alloc_bw[i], m->bw_limit[i]);
}

/**
 * Print CXL Ports 
 *
 * @param	struct cxl_switch_stat* to use to print
 * @param 	indent The number of spaces to indent the printed text
 */
void cxls_prnt_ports(struct cxl_switch *s, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";
	int i;

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	// Print fields
	printf("%sports:\n", space);

	for ( i = 0 ; i < s->num_ports ; i++) 
	{
		printf("%s  %02u:\n", space,i);
		cxls_prnt_port(&s->ports[i], indent + 2 + CXLN_INDENT);
	}
}

/**
 * Print the CXL Port Information
 *
 * @param	struct port* to print
 * @param 	indent The number of spaces to indent the printed text
 */
void cxls_prnt_port(struct cxl_port *p, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	// Print fields
	printf("%sstate:                   %u\t\t%s\n", 	space, p->state, 	fmps(p->state));
   	printf("%sdv:                      %u\t\t%s\n", 	space, p->dv, 		fmdv(p->dv));
   	printf("%sdt:                      %u\t\t%s\n", 	space, p->dt,		fmdt(p->dt));
   	printf("%scv:                      0x%02x\n", 		space, p->cv);
   	printf("%smax_link_width:          %u\n", 			space, p->mlw);
   	printf("%sneg_link_width:          %u\n", 			space, p->nlw);
   	printf("%sspeeds:                  0x%02x\n", 		space, p->speeds);
   	printf("%smax_link_speed:          %u\t\t%s\n", 	space, p->mls, 		fmms(p->mls));
   	printf("%scur_link_speed:          %u\t\t%s\n", 	space, p->cls, 		fmms(p->cls));
   	printf("%sltssm:                   %u\t\t%s\n", 	space, p->ltssm,	fmls(p->ltssm));
   	printf("%sfirst_lane:              %u\n", 			space, p->lane);
	printf("%sLane Reversal State      %d\n", 			space, p->lane_rev);
	printf("%sPCIe Reset State         %d\n", 			space, p->perst);
	printf("%sPort Presence pin state  %d\n", 			space, p->prsnt);
	printf("%sPower Control State      %d\n", 			space, p->pwrctrl);
   	printf("%sld:                      %u\n", 			space, p->ld);
   	printf("%sDevice Name              %s\n", 			space, p->device_name);

	if (p->cfgspace != NULL) 
	{
		pcie_prnt_cfgspace(p->cfgspace, indent);
		autl_prnt_buf(p->cfgspace, 1024, 16, 1);	
	}

	if (p->mld != NULL) 
		cxls_prnt_mld(p->mld, indent);
}

/**
 * Print the CXL VCS List 
 *
 * @param	struct cxl_switch_state* to print from 
 * @param 	indent The number of spaces to indent the printed text
 */
void cxls_prnt_vcss(struct cxl_switch *s, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";
	int i;

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	// Print fields
	printf("%svcss:\n", space);

	for ( i = 0 ; i < s->num_vcss ; i++) 
	{
		printf("%s  %02u:\n", space, i);
		cxls_prnt_vcs(&s->vcss[i], indent + 2 + CXLN_INDENT);
	}
}

/**
 * Print information for a single CXL VCS 
 *
 * @param	struct vcs* to print
 * @param 	indent The number of spaces to indent the printed text
 */
void cxls_prnt_vcs(struct cxl_vcs *v, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";
	int i;

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	// Print fields of the VCS
	printf("%sstate:          %u\t\t%s\n", 	space, v->state, 			fmvs(v->state));
   	printf("%suspid:          %u\n", 		space, v->uspid);
   	printf("%snum_vppb:       %u\n", 		space, v->num);
	printf("%svppbs:\n",					space);

	// Print the vPPBs of the VCS
	for ( i = 0 ; i < v->num ; i++) 
	{
		printf("%s  %u:\n", space, i);
		cxls_prnt_vppb(&v->vppbs[i], indent + 2 + CXLN_INDENT);
	}
}

/**
 * Print information for a single CXL vPPB
 *
 * @param	struct vppb* to print
 * @param 	indent The number of spaces to indent the printed text
 */
void cxls_prnt_vppb(struct cxl_vppb *b, unsigned indent)
{
	char space[CXLN_MAX_INDENT] = "                                ";

	// Handle indent
	if ( indent >= CXLN_MAX_INDENT ) 
		indent = CXLN_MAX_INDENT; 
	space[indent] = 0;

	// Print fields of the VCS
	printf("%sldid:           %u\n", 		space, b->ldid);
	printf("%sppid:           %u\n", 		space, b->ppid);
	printf("%sbind_status:    %u\t\t%s\n", 	space, b->bind_status, 	fmbs(b->bind_status));
}

