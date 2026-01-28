# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    # Select Ubuntu Box
    config.vm.box = "generic/ubuntu2204"

    # Syncronize folder
    config.vm.synced_folder ".", "/home/vagrant/module", type: "nfs", nfs_version: 4, nfs_udp: false, mount_options: ["actimeo=1"]

    # Specific config for libvirt provider
    config.vm.provider :libvirt do |libvirt|
        libvirt.memory = 2048
        libvirt.cpus = 2
        libvirt.video_type = "virtio"
    end

    # Fallback to VirtualBox provider
    config.vm.provider :virtualbox do |vb|
        vb.memory = "2048"
        vb.cpus = 2
    end

    # Provisioning script
    config.vm.provision "shell", inline: <<-SHELL
        export DEBIAN_FRONTEND=noninteractive
        apt-get -y update
        apt-get install -y build-essential linux-headers-$(uname -r) libelf-dev nfs-common

        echo "--------------------------------------------------"
        echo "Ubuntu is ready!"
        echo "Connect with:                 vagrant ssh"
        echo "Go to the folder:             cd ~/module"
        echo "Setup the environment with:   make setup"
        echo "To build the module, run:     make"
        echo "--------------------------------------------------"
    SHELL
end