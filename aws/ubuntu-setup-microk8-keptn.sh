#!/bin/bash -x
## Commands for Ubuntu Server 18.04 LTS (HVM), SSD Volume Type
## These script will install the following components:
## Microkubernetes

## Set TENANT and API TOKEN
export TENANT=
export PAASTOKEN=
export APITOKEN=
LOGFILE='/tmp/install.txt'

##Create installer Logfile
printf "\n\n***** Init Installation ***\n" >> $LOGFILE 2>&1 
{ date ; apt update; whoami ; echo Setting up microkubernetes with keptn and oneagent for tenant: $TENANT with Api-Token: $APITOKEN and PaaS-Token: $PAASTOKEN; } >> $LOGFILE ; chmod 777 $LOGFILE

printf "\n\ninstall jq***\n" >> $LOGFILE 2>&1 
apt install jq -y >> $LOGFILE 2>&1


printf "\n\n***** Update and install docker***\n" >> $LOGFILE 2>&1 
{ apt install docker.io -y ;\ 
 service docker start ;\
 usermod -a -G docker ubuntu ;} >> $LOGFILE 2>&1

# Install Kubernetes 1.16
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

#Copy Aliases
cp /root/.bash_aliases /home/ubuntu/.bash_aliases
cp /root/.bash_aliases /home/dynatrace/.bash_aliases

# Add alias to Kubectl
snap alias microk8s.kubectl kubectl 

#Start Micro Enable Default Modules as Ubuntu
# Passing the commands to ubuntu since it has microk8s in its path and also does not have password enabled otherwise the install will fail
{ echo "\n\n***** Starting microk8s *****\n" ;\
sudo -H -u ubuntu bash -c 'microk8s.start && microk8s.enable dns storage ingress dashboard' ;} >> $LOGFILE 2>&1

# Download YAML files from Github and unpack them
git clone https://github.com/sergiohinojosa/kubernetes-deepdive /home/ubuntu/kubernetes  

# Set permisions
chown ubuntu:ubuntu -R /home/ubuntu/kubernetes/


git clone --branch 0.6.1 https://github.com/keptn/examples.git /home/ubuntu/examples --single-branch
chown ubuntu:ubuntu -R /home/ubuntu/examples/

printf "\n\n***** Create Istio NS and route traffic to istio ingress-gateway ****\n"
{ sudo -H -u ubuntu bash -c 'kubectl create ns istio-system' ;\
sudo -H -u ubuntu bash -c 'cd /home/ubuntu/kubernetes/keptn/setup && sh route_istio.sh' ;} >> $LOGFILE 2>&1

# dynatrace no rights for kubectl, docker?

# Allow access to K8 Dashboard withouth login
# Create ingresses
# { sudo -H -u ubuntu bash -c 'kubectl apply -f /home/dynatrace/kubernetes/k8-dashboard/skip-login-in-k8-dashboard.yaml' ;\
# sudo -H -u ubuntu bash -c 'cd /home/dynatrace/kubernetes/keptn/setup && sh route_istio.sh' ;} >> $LOGFILE 2>&1

## Installation of Active Gate
## { wget -nv -O activegate.sh "$TENANT/api/v1/deployment/installer/gateway/unix/latest?Api-Token=$PAASTOKEN&arch=x86&flavor=default"
## sh activegate.sh ;} >> $LOGFILE 2>&1 

## Installation of Keptn
{  printf "\n\n***** Downloading Keptn ***** \n" ; wget https://github.com/keptn/keptn/releases/download/0.6.0/0.6.0_keptn-linux.tar ;\
tar -xvf 0.6.0_keptn-linux.tar ;\
chmod +x keptn ;\
mv keptn /usr/local/bin/keptn ;}   >> $LOGFILE 2>&1

# Installation of Helm Client
{  printf "\n\n***** Downloading HELM *****\n" ; wget -O getHelm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get ;\
chmod +x getHelm.sh ;\
./getHelm.sh -v v2.12.3 ;\
helm init ;}   >> $LOGFILE 2>&1

{  printf "\n\n*****Configure Public Domain for Microk8s  ***** \n" ;\
export PUBLIC_IP=$(curl -s ifconfig.me) ;\
PUBLIC_IP_AS_DOM=$(echo $PUBLIC_IP | sed 's~\.~-~g') ;\
export DOMAIN="${PUBLIC_IP_AS_DOM}.nip.io" ;\
printf "Public DNS: $DOMAIN"
sudo -H -u ubuntu bash -c "kubectl create configmap keptn-domain --from-literal=domain=$DOMAIN" ;} >> $LOGFILE 2>&1

{ printf "\n\n***** Waiting for pods to start.... we sleep for 1 minute before the installation of Keptn *****\n" ;\
sleep 1m ;} >> $LOGFILE 2>&1

{ printf "\n\n***** Kick installation of Keptn *****\n" ;\
sudo -H -u ubuntu bash -c 'echo 'y' | keptn install --platform=kubernetes --istio-install-option=Overwrite --gateway=LoadBalancer --keptn-installer-image=shinojosa/keptninstaller:6.1.customdomain' ;} >> $LOGFILE 2>&1


{ printf "\n\n***** Waiting 1 minute for keptn to initialize. Then we recycle the NGINX pods  *****\n" ;\
sleep 1m ;} >> $LOGFILE 2>&1

# NoteToSelf, in micro1.16 the nginx has an own namespace. Why do 1.15 need two pods? who knows....
{ printf "\n\n***** After Keptn installation recycle ingress NGINX Pods so the routing to istio works *****\n" ;\
sudo -H -u ubuntu bash -c 'kubectl delete po --all' ;} >> $LOGFILE 2>&1

# Allow unencrypted password via SSH for login
# Restart the SSHD Service
{ printf "\n\n***** Allow Password authentication and restarting SSH service *****\n" ;\
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config ;\
service sshd restart ;} >> $LOGFILE 2>&1


# Now lets install Dynatrace
# Create secret
# Deploy Dynatrace service
# Deploy SLI Service 
# Deploy Operator via Keptn 

{ printf "\n\n***** Installing and configuring Dynatrace on the Cluster *****\n\n" ;\
sudo -H -u ubuntu bash -c "kubectl -n keptn create secret generic dynatrace --from-literal=\"DT_TENANT=$TENANT\" --from-literal=\"DT_API_TOKEN=$APITOKEN\"  --from-literal=\"DT_PAAS_TOKEN=$PAASTOKEN\"" ;\
sudo -H -u ubuntu bash -c "kubectl apply -f https://raw.githubusercontent.com/keptn-contrib/dynatrace-service/0.6.1/deploy/manifests/dynatrace-service/dynatrace-service.yaml" ;\
sudo -H -u ubuntu bash -c "kubectl apply -f https://raw.githubusercontent.com/keptn-contrib/dynatrace-sli-service/0.3.0/deploy/service.yaml" ;\
sudo -H -u ubuntu bash -c "keptn configure monitoring dynatrace" ;} >> $LOGFILE 2>&1

# Deploy Bridge EAP
{ printf "\n\n***** Deploy Bridge EAP and Expose via VS  *****\n\n" ;\
sudo -H -u ubuntu bash -c 'kubectl -n keptn set image deployment/bridge bridge=keptn/bridge2:20200308.0859 --record' ;\
sudo -H -u ubuntu bash -c 'kubectl -n keptn set image deployment/configuration-service configuration-service=keptn/configuration-service:20200308.0859 --record' ;\
sudo -H -u ubuntu bash -c 'kubectl -n keptn-datastore set image deployment/mongodb-datastore mongodb-datastore=keptn/mongodb-datastore:20200308.0859 --record' ;} >> $LOGFILE 2>&1

# Expose bridge via VS /home/ubuntu/kubernetes/keptn/
{ printf "\n\n*****  Expose Bridge via VS  *****\n\n" ;\
DOMAIN=$(sudo -H -u ubuntu bash -c "kubectl get cm -n keptn keptn-domain -ojsonpath={.data.app_domain}") ;\
sudo -H -u ubuntu bash -c "cat /home/ubuntu/kubernetes/keptn/expose-bridge/manifests/bridge.yaml | sed 's~domain.placeholder~'\"$DOMAIN\"'~' > /home/ubuntu/kubernetes/keptn/expose-bridge/manifests/gen/bridge.yaml" ;\
sudo -H -u ubuntu bash -c "kubectl apply -f /home/ubuntu/kubernetes/keptn/expose-bridge/manifests/gen/bridge.yaml" ;}  >> $LOGFILE 2>&1

# Unleash Server? 
{ printf "\n\n*****  Deploy Unleash-Server  *****\n\n" ;\
sudo -H -u ubuntu bash -c "cd /home/ubuntu/examples/unleash-server/ && sh /home/ubuntu/kubernetes/keptn/setup/deploy_unleashserver.sh" 
;} >> $LOGFILE 2>&1

cd examples/onboarding-carts

# Onboard Services? 
# To be sure restart datastore?? 
#kubectl delete po -n keptn-datastore --all
printf "\n\n***** Installation complete :) *****\n" >> $LOGFILE 2>&1