#!/bin/bash -x
## Commands for Ubuntu Server 18.04 LTS (HVM), SSD Volume Type
## These script will install the following components:
## Microkubernetes 1.15, Keptn 6.1 with Istio 1.5 and Helm 1.2, the OneAgent and an ActiveGate

# Log duration
SECONDS=0

## Set TENANT and API TOKEN
export TENANT=
export PAASTOKEN=
export APITOKEN=
LOGFILE='/tmp/install.txt'

##Create installer Logfile
printf "\n\n***** Init Installation ***\n" >> $LOGFILE 2>&1 
{ date ; apt update; whoami ; echo Setting up microkubernetes with keptn and oneagent for tenant: $TENANT with Api-Token: $APITOKEN and PaaS-Token: $PAASTOKEN; } >> $LOGFILE ; chmod 777 $LOGFILE

printf "\n\n***** Update and install docker***\n" >> $LOGFILE 2>&1 
{ apt install docker.io -y ;\ 
 service docker start ;\
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
useradd -s /bin/bash -d /home/dynatrace/ -m -G sudo -p $(openssl passwd -1 dynatrace) dynatrace

# Add Dynatrace & Ubuntu to microk8s & docker
usermod -a -G microk8s ubuntu
usermod -a -G microk8s dynatrace
usermod -a -G docker dynatrace
usermod -a -G docker ubuntu

printf "\n\n*****  Add ProTip alias ***** \n" >> $LOGFILE 2>&1 
echo "
# Alias for ease of use of the CLI
alias hg='history | grep' 
alias h='history' 
alias vaml='vi -c \"set syntax:yaml\" -' 
alias vson='vi -c \"set syntax:json\" -' 
alias pg='ps -aux | grep' " > /root/.bash_aliases

# Copy Aliases
cp /root/.bash_aliases /home/ubuntu/.bash_aliases
cp /root/.bash_aliases /home/dynatrace/.bash_aliases

# Add alias to Kubectl
snap alias microk8s.kubectl kubectl 

# Add Snap to the system wide environment. 
sed -i 's~/usr/bin:~/usr/bin:/snap/bin:~g' /etc/environment

#Start Micro Enable Default Modules as Ubuntu
# Passing the commands to ubuntu since it has microk8s in its path and also does not have password enabled otherwise the install will fail
{ echo "\n\n***** Starting microk8s *****\n" ;\
sudo -H -u dynatrace bash -c 'microk8s.start && microk8s.enable dns storage ingress dashboard' ;} >> $LOGFILE 2>&1

# Copy the Workshop from Github and unpack them
git clone --branch 0.6.1 https://github.com/acm-workshops/keptn-workshop.git /home/dynatrace/keptn-workshop  --single-branch

# TODO Dont clone this repo, KISS.
# is this needed? I can add a subfolder and merge?
git clone --branch 0.6.1 https://github.com/keptn/examples.git /home/dynatrace/examples --single-branch

# TODO Dont clone this repo, KISS.
# Download YAML files from Github and unpack them
git clone https://github.com/sergiohinojosa/kubernetes-deepdive /home/dynatrace/kubernetes  

# Change owner of cloned folders
chown dynatrace:dynatrace -R /home/dynatrace/

# Installation of istio 1.5 
{  printf "\n\n*****Install istio 1.5 into /opt and add it to user/local/bin ***** \n" ;\
curl -L https://istio.io/downloadIstio | sh - ;\
mv istio-1.5.0 /opt/istio-1.5.0 ;\
chmod +x -R /opt/istio-1.5.0/ ;\
ln -s /opt/istio-1.5.0/bin/istioctl /usr/local/bin/istioctl ;\
sudo -H -u dynatrace bash -c "echo 'y' | istioctl manifest apply" ;} >> $LOGFILE 2>&1


{ printf "\n\n***** Waiting for pods to start.... we sleep for 1 minute *****\n" ;\
sleep 1m ;} >> $LOGFILE 2>&1


# Allow access to K8 Dashboard withouth login
# Create ingresses
# { sudo -H -u dynatrace bash -c 'kubectl apply -f /home/dynatrace/kubernetes/k8-dashboard/skip-login-in-k8-dashboard.yaml' ;\
# sudo -H -u dynatrace bash -c 'cd /home/dynatrace/kubernetes/keptn/setup && sh route_istio.sh' ;} >> $LOGFILE 2>&1

## Installation of Active Gate
{ wget -nv -O activegate.sh "$TENANT/api/v1/deployment/installer/gateway/unix/latest?Api-Token=$PAASTOKEN&arch=x86&flavor=default"
sh activegate.sh ;} >> $LOGFILE 2>&1 

# Installation of Helm Client
{  printf "\n\n***** Downloading HELM *****\n" ; wget -O getHelm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get ;\
chmod +x getHelm.sh ;\
./getHelm.sh -v v2.12.3 ;\
helm init ;}   >> $LOGFILE 2>&1

## Installation of Keptn
{  printf "\n\n***** Downloading KEPTN ***** \n" ; wget -q -O keptn.tar https://github.com/keptn/keptn/releases/download/0.6.1/0.6.1_keptn-linux.tar ;\
tar -xvf keptn.tar ;\
chmod +x keptn ;\
mv keptn /usr/local/bin/keptn ;}   >> $LOGFILE 2>&1


printf "\n\n***** Install CertManager ****\n"
{ sudo -H -u dynatrace bash -c 'kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.14.0/cert-manager.yaml' ;} >> $LOGFILE 2>&1


printf "\n\n***** Route Traffic to IstioGateway and Create SSL certificates for Istio Endpoints ****\n"
{ sudo -H -u dynatrace bash -c 'cd /home/dynatrace/keptn-workshop/setup && sh expose-ssl-istio.sh' ;} >> $LOGFILE 2>&1

{  printf "\n\n*****Configure Public Domain for Microk8s  ***** \n" ;\
export PUBLIC_IP=$(curl -s ifconfig.me) ;\
PUBLIC_IP_AS_DOM=$(echo $PUBLIC_IP | sed 's~\.~-~g') ;\
export DOMAIN="${PUBLIC_IP_AS_DOM}.nip.io" ;\
printf "Public DNS: $DOMAIN"
sudo -H -u dynatrace bash -c "kubectl create configmap keptn-domain --from-literal=domain=$DOMAIN" ;} >> $LOGFILE 2>&1


{ printf "\n\n***** Install Keptn *****\n" ;\
sudo -H -u dynatrace bash -c 'echo 'y' | keptn install --platform=kubernetes --istio-install-option=Reuse --gateway=LoadBalancer --keptn-installer-image=shinojosa/keptninstaller:6.1.customdomain' ;} >> $LOGFILE 2>&1

# Authorize keptn
printf "\nFor authorizing Keptn type
keptn auth --endpoint=https://api.keptn.$(kubectl get cm -n keptn keptn-domain -ojsonpath={.data.app_domain}) --api-token=$(kubectl get secret keptn-api-token -n keptn -ojsonpath={.data.keptn-api-token} | base64 --decode)\n"

{ printf "\n\n***** Waiting 1 minutes for keptn to initialize. *****\n" ;\
sleep 1m ;} >> $LOGFILE 2>&1

# Remove after test NoteToSelf, in micro1.16 the nginx has an own namespace. Why do 1.15 need two pods? who knows....
# { printf "\n\n***** After Keptn installation recycle ingress NGINX Pods so the routing to istio works *****\n" ;\
# sudo -H -u dynatrace bash -c 'kubectl delete po --all' ;} >> $LOGFILE 2>&1


# { printf "\n\n***** Wait another minute for NGINX pods to initialize. *****\n" ;\
# sleep 1m ;} >> $LOGFILE 2>&1

# Install OA

# Expose Bridge

# Unleash

# Installation finish, print time.
DURATION=$SECONDS
printf "\n\n***** Installation complete :) *****\nIt took $(($DURATION / 60)) minutes and $(($DURATION % 60)) seconds " >> $LOGFILE 2>&1