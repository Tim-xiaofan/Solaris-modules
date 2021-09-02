#install driver on x86_64 platform
drv="dummy"
conf="${drv}.conf"
#sudo cp "${drv}.conf" /usr/kernel/drv
#cp ${drv} /tmp/
#sudo ln -s /tmp/${drv} /usr/kernel/drv/amd64/${drv}
#sudo add_drv ${drv}
#sudo modinfo -i ${drv}
#cat /etc/name_to_major | grep ${drv}

sudo modunload -i ${drv}
sudo rem_drv ${drv}
sudo rm -f /usr/kernel/drv/amd64/${drv} /tmp/${drv} /usr/kernel/drv/${conf}
