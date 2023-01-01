#/bin/sh

# install dependencies for building iproute2
apt update
DEBIAN_FRONTEND=noninteractive apt upgrade -y
apt install -y bison flex clang gcc llvm libelf-dev bc libssl-dev tmux trace-cmd linux-headers-`uname -r`

# update iproute2
sudo apt install -y pkg-config bison flex make gcc
cd /tmp
wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.5.0.tar.gz
tar -xzvf ./iproute2-5.5.0.tar.gz
cd ./iproute2-5.5.0

sudo make && sudo make install

# enable gtp and install
cd /home/vagrant
sudo apt -y install libtalloc-dev libpcsclite-dev libmnl-dev autoconf libtool
sudo ldconfig -v
git clone git://git.osmocom.org/libgtpnl.git
cd libgtpnl
autoreconf -fi
./configure
make
sudo make install
sudo ldconfig

# install dependenceis for bpf
apt install -y gcc-multilib