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

/* ENUMERATIONS ==============================================================*/

/* STRUCTS ===================================================================*/

/* PROTOTYPES ================================================================*/

/* GLOBAL VARIABLES ==========================================================*/

/* FUNCTIONS =================================================================*/

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
	unsigned i;
	struct cxl_port *p;
	struct cxl_vcs *v;
	struct cxl_switch *s;

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
	s->num_ports = ports;
	s->num_vcss = vcss;
	s->num_vppbs = vppbs;
	s->num_decoders = 42;

	// Initialize Mutex
	pthread_mutex_init(&s->mtx, NULL);

	// 3: Initalize Ports 
	s->ports = calloc(ports, sizeof(struct cxl_port));
	if ( s->ports == NULL ) 
	{
		errno = ENOMEM;
		goto end_state; 
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
	}

	// 4: Initalize VCSs
	s->vcss = calloc(vcss, sizeof(struct cxl_vcs));
	if ( s->vcss == NULL ) 
	{
		errno = ENOMEM;
		goto end_ports; 
	}

	// Set default vcs values
	for ( i = 0 ; i < vcss ; i++) 
	{
		v 			= &s->vcss[i];
		v->vcsid	= i;
		v->state	= FMVS_DISABLED;
		v->uspid	= 0;
		v->num		= 0;

		// Set the vcs->vppb[] array to zero
		memset(v->vppbs, 0, CXLN_VPPBS_PER_VCS * sizeof(struct cxl_vppb));
	}

 	// 5: Initalize PCIe config space register
	for ( i = 0 ; i < ports ; i++ )
	{
		s->ports[i].cfgspace = calloc(1, CXLN_CFG_SPACE);
		if(s->vcss == NULL)
		{
			errno = ENOMEM;
			goto end_cfgspace; 
		}
	}

	goto end;

end_cfgspace:

	for ( i = 0 ; i < ports ; i++ ) 
	{
		if( s->ports[i].cfgspace != NULL ) 
		{
			free(s->ports[i].cfgspace);
			s->ports[i].cfgspace = NULL;
		}
	}

	free(s->vcss);
	s->vcss = NULL;

end_ports:

	free(s->ports);
	s->ports = NULL;

end_state:

	free(s);
	s = NULL;

end:

	return s;
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
	unsigned i, k;
	struct cxl_port *p;
	struct cxl_device *d;
	
	if (s == NULL) 
		return;
	
	// 1: Destroy mutex
	pthread_mutex_destroy(&s->mtx);

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
	
	// 6: Free VCSs
	if ( s->vcss != NULL )  
	{
		free(s->vcss);
		s->vcss = NULL;
	}

	// 7: Free Ports
	if ( s->ports != NULL ) 
	{
		free(s->ports);
		s->ports = NULL;
	}

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

	free(s);
	s = NULL;
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

