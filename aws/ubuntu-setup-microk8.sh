#!/bin/bash
## Commands for Ubuntu Server 16.04 LTS (HVM), SSD Volume Type - ami-0cbe2951c7cd54704
## These script will install the following components:
## Microkubernetes

## Set TENANT and API TOKEN
export TENANT=
export PAASTOKEN=

##Create installer Logfile
{ date ; apt update; whoami ; echo Setting up ec2 for tenant: $TENANT with Api-Token: $PAASTOKEN ; } >> /tmp/install.txt ; chmod 777 /tmp/install.txt

# Install JQ
apt install jq -y >> /tmp/install.txt 2>&1

##Update and install docker
{ apt install docker.io -y ;\
 service docker start ;\
 usermod -a -G docker ubuntu ;} >> /tmp/install.txt 2>&1

# Install Kubernetes 1.16
{ snap install microk8s --channel=1.16/stable --classic ;\
bash -c "echo \"--allow-privileged=true\" >> /var/snap/microk8s/current/args/kube-apiserver" ;} >> /tmp/install.txt 2>&1

# Update IPTABLES
# Allow traffic for pods internal and external
{ iptables -P FORWARD ACCEPT ;\
ufw allow in on cni0 && sudo ufw allow out on cni0 ;\
ufw default allow routed ;} >> /tmp/install.txt 2>&1

# Create user Dynatrace, we specify bash login, home directory, password and add him to the sudoers
useradd -s /bin/bash -d /home/dynatrace/ -m -G sudo -p $(openssl passwd -1 dynatrace) dynatrace

# Add Dynatrace & Ubuntu to microk8s & docker
usermod -a -G microk8s ubuntu
usermod -a -G microk8s dynatrace
usermod -a -G docker dynatrace
usermod -a -G docker ubuntu

# Add ProTip alias
echo "
# Alias for ease of use of the CLI
alias hg='history | grep' 
alias h='history' 
alias vaml='vi -c \"set syntax:yaml\" -' 
alias vson='vi -c \"set syntax:json\" -' 
alias pg='ps -aux | grep' " > /root/.bash_aliases

#Copy Aliases
cp /root/.bash_aliases /home/ubuntu/.bash_aliases
cp /root/.bash_aliases /home/dynatrace/.bash_aliases

# Add alias to Kubectl
snap alias microk8s.kubectl kubectl 

#Start Micro Enable Default Modules as Ubuntu
# Passing the commands to ubuntu since it has microk8s in its path and also does not have password enabled otherwise the install will fail
{ echo "starting microk8s\n" ;\
sudo  -H -u ubuntu bash -c 'microk8s.start && microk8s.enable dns storage ingress dashboard' ;} >> /tmp/install.txt 2>&1

# Download YAML files from Github and unpack them
git clone https://github.com/sergiohinojosa/kubernetes-deepdive /home/dynatrace/kubernetes  

# Set permisions
chown dynatrace:dynatrace -R /home/dynatrace/kubernetes/

# Allow access to K8 Dashboard withouth login
# Create ingresses
{ sudo -H -u dynatrace bash -c 'kubectl apply -f /home/dynatrace/kubernetes/k8-dashboard/skip-login-in-k8-dashboard.yaml' ;\
sudo -H -u dynatrace bash -c 'cd /home/dynatrace/kubernetes/ingress/ && sh createingress.sh' ;} >> /tmp/install.txt 2>&1

## Installation of Active Gate
{ wget -nv -O activegate.sh "$TENANT/api/v1/deployment/installer/gateway/unix/latest?Api-Token=$PAASTOKEN&arch=x86&flavor=default"
sh activegate.sh ;} >> /tmp/install.txt 2>&1 

# Allow unencrypted password via SSH for login
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
# Restart the ActiveGate
service sshd restart