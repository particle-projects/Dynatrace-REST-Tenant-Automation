#!/bin/bash
## Commands for Ubuntu Server 16.04 LTS (HVM), SSD Volume Type - ami-0cbe2951c7cd54704
## These script will install the following components:
## Microkubernetes
# Log duration
SECONDS=0

## Set TENANT and API TOKEN
export TENANT=
export PAASTOKEN=
export APITOKEN=
LOGFILE='/tmp/install.log'

##Create installer Logfile
printf "\n\n***** Init Installation ****\n" >> $LOGFILE 2>&1 

# clean protocol
PROTOCOL="https://";DT_TENANT=${TENANT#"$PROTOCOL"} ; printf "This is the Tenant:$DT_TENANT"  ;\

{ date ; apt update; whoami ; printf "\n\n********** Setting up microk8s (SingleNode K8s Dev Cluster) with Keptn and the OneAgent **********\n\nTenant: $DT_TENANT \nApi-Token: $APITOKEN \nPaaS-Token: $PAASTOKEN \n\n" ;} >> $LOGFILE ; chmod 777 $LOGFILE

printf "\n\n***** Update and install docker and JQ***\n" >> $LOGFILE 2>&1 
{ apt install docker.io -y ;\ 
service docker start ;\
apt install jq -y ;\
usermod -a -G docker ubuntu ;} >> $LOGFILE 2>&1

# Install Kubernetes 1.15
printf "\n\n***** Install Microk8s 1.15 and allow the KubeApiServer to run priviledged pods***\n" >> $LOGFILE 2>&1 
{ snap install microk8s --channel=1.15/stable --classic ;\
bash -c "echo \"--allow-privileged=true\" >> /var/snap/microk8s/current/args/kube-apiserver" ;} >> $LOGFILE 2>&1

printf "\n\n***** Update IPTABLES,  Allow traffic for pods internal and external***\n" >> $LOGFILE 2>&1 
{ iptables -P FORWARD ACCEPT ;\
ufw allow in on cni0 && sudo ufw allow out on cni0 ;\
ufw default allow routed ;} >> $LOGFILE 2>&1

printf "\n\n*****  Create user 'dynatrace', we specify bash login, home directory, password and add him to the sudoers\n" >> $LOGFILE 2>&1 
# Add user with password so SSH login with password is possible. Share same home directory
# TODO - Enhance - paramatirize user and password with RTA CSV Variables
useradd -s /bin/bash -d /home/ubuntu/ -m -G sudo -p $(openssl passwd -1 dynatrace) dynatrace
# Share own groups with each other
usermod -a -G ubuntu dynatrace
usermod -a -G dynatrace ubuntu

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

# Add alias to Kubectl (Bash completion for kubectl is already enabled)
snap alias microk8s.kubectl kubectl 

# Add Snap to the system wide environment. 
sed -i 's~/usr/bin:~/usr/bin:/snap/bin:~g' /etc/environment

# Start Micro Enable Default Modules as Ubuntu
# Passing the commands to ubuntu since it has microk8s in its path and also does not have password enabled otherwise the install will fail
{ echo "\n\n***** Starting microk8s *****\n" ;\
sudo -H -u ubuntu bash -c 'microk8s.start && microk8s.enable dns storage ingress dashboard registry' ;} >> $LOGFILE 2>&1

# Download kubernetes-deepdive repo
git clone https://github.com/sergiohinojosa/kubernetes-deepdive /home/ubuntu/workshop  

# Change owner of cloned folders
chown ubuntu:ubuntu -R /home/ubuntu/

{  printf "\n\n***** Save Dynatrace credentials *****\n" ;\
sudo -H -u ubuntu bash -c "cd /home/ubuntu/workshop/dynatrace/ ; bash save-credentials.sh \"$DT_TENANT\" \"$PAASTOKEN\" \"$APITOKEN\"" ;} >> $LOGFILE 2>&1


{  printf "\n\n***** Installation of Active Gate *****\n" ;\
wget -nv -O activegate.sh "https://$DT_TENANT/api/v1/deployment/installer/gateway/unix/latest?Api-Token=$PAASTOKEN&arch=x86&flavor=default" ;\
sh activegate.sh ;} >> $LOGFILE 2>&1 

## TODO: Enhacement - Modify with wait and check status of istio
{ printf "\n\n***** Waiting for pods to start.... we sleep for 30 sec  *****\n" ;\
sleep 30s ;} >> $LOGFILE 2>&1

# Installation of istio 1.5.1
{  printf "\n\n*****Install istio 1.5 into /opt and add it to user/local/bin ***** \n" ;\
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.5.1 sh - ;\
mv istio-1.5.1 /opt/istio-1.5.1 ;\
chmod +x -R /opt/istio-1.5.1/ ;\
ln -s /opt/istio-1.5.1/bin/istioctl /usr/local/bin/istioctl ;\
sudo -H -u ubuntu bash -c "echo 'y' | istioctl manifest apply" ;} >> $LOGFILE 2>&1


# Installation of Helm Client
{  printf "\n\n***** Downloading HELM *****\n" ; wget -O getHelm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get ;\
chmod +x getHelm.sh ;\
./getHelm.sh -v v2.12.3 ;\
helm init ;}   >> $LOGFILE 2>&1

printf "\n\n***** Install CertManager ****\n"
{ sudo -H -u ubuntu bash -c 'kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.14.0/cert-manager.yaml' ;\
printf '\nWe wait for 40 sec for certmgr to deploy\n';\
sleep 40s ;} >> $LOGFILE 2>&1

# Getting the public DOMAIN
export PUBLIC_IP=$(curl -s ifconfig.me) ;\
PUBLIC_IP_AS_DOM=$(echo $PUBLIC_IP | sed 's~\.~-~g') ;\
export DOMAIN="${PUBLIC_IP_AS_DOM}.nip.io" ;\
printf "Public DNS: $DOMAIN"

printf "\n\n***** Route Traffic to IstioGateway and Create SSL certificates for Istio Endpoints ****\n"
{ sudo -H -u ubuntu bash -c "cd /home/ubuntu/workshop/istio/setup && sh expose-ssl-istio.sh \"$DOMAIN\"" ;} >> $LOGFILE 2>&1

# Route K8 Dashboard 
{  printf "\n\n*****Allow access to K8 Dashboard withouth login ***** \n" ;\
 sudo -H -u ubuntu bash -c "cd /home/ubuntu/workshop/k8-services && bash expose-k8-services.sh \"$DOMAIN\"" ;} >> $LOGFILE 2>&1

{ printf "\n\n*****Allow -rwx for the user and group (dynatrace) for all files in the home directory ***** \n" ;\
chmod -R 774 /home/ubuntu/* ;} >> $LOGFILE 2>&1

# Allow unencrypted password via SSH for login
# Restart the SSHD Service
{ printf "\n\n***** Allow Password authentication and restarting SSH service *****\n" ;\
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config ;\
service sshd restart ;} >> $LOGFILE 2>&1

# Installation finish, print time.
DURATION=$SECONDS
printf "\n\n***** Installation complete :) *****\nIt took $(($DURATION / 60)) minutes and $(($DURATION % 60)) seconds " >> $LOGFILE 2>&1

