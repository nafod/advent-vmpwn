# kill stupid vmware tools processes
sudo insmod ./pwn.ko
sudo rmmod pwn
sudo dmesg | tail
python leakaddr.py
