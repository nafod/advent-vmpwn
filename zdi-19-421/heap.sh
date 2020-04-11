sudo pkill vmtoolsd
sudo pkill -f vmware-vmblock-fuse
sudo pkill vmware
sudo service gdm3 stop
sudo service gdm stop
sudo bash -c 'echo 1 > /sys/dev/block/11\:0/device/delete'
vmware-rpctool 'vmx.set_option synctime 1 0' > /dev/null
vmware-rpctool 'vmx.set_option time.synchronize.tools.enable 1 0' >/dev/null
