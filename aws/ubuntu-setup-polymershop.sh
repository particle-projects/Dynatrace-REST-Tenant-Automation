#!/bin/bash
## Commands for Ubuntu Server 16.04 LTS (HVM), SSD Volume Type - ami-0cbe2951c7cd54704
## These script will install the following components:
# - OneAgent 
# - ActiveGate with Private Synthetic Monitors enabled (and its dependencies. Read the requirements.
# - Docker
# - BankJobs shinojosa/bankjob:v0.2 from DockerHub
# - EasyTravel, Legacy 8080,8079 / Angular 9080 / WebLauncher 8094 


## Set TENANT and API TOKEN
export TENANT=
export APITOKEN=


##Create installer Logfile
{ date ; apt update; whoami ; echo Setting up ec2 for tenant: $TENANT with Api-Token: $APITOKEN ; } >> /tmp/install.txt ; chmod 777 /tmp/install.txt

##Update and install docker
{ apt install docker.io -y ;\
 service docker start ;\
 usermod -a -G docker ubuntu ;} >> /tmp/install.txt 2>&1

### ----------------------
# https://www.dynatrace.com/support/help/how-to-use-dynatrace/synthetic-monitoring/browser-monitors/browser-monitors-in-private-locations/?red-hat%3C-%3Ecentos=centos 
# Preparation for ActiveGate  

{ apt-get -y install xvfb x11-xkb-utils xfonts-100dpi xfonts-75dpi xfonts-scalable ;\
apt-get -y install libasound2 libatk-bridge2.0-0 libatk1.0-0 libc6:amd64 libcairo2 libcups2 libgdk-pixbuf2.0-0 libgtk-3-0 libnspr4 libnss3 libxss1 xdg-utils ;\
wget -nv -O chromium-browser_73-ubuntu.16.04.1_amd64.deb https://s3.amazonaws.com/synthetic-packages/Chromium/deb/chromium-browser_73-ubuntu.16.04.1_amd64.deb ;\
wget -nv -O chromium-codecs-ffmpeg-extra_73-ubuntu.16.04.1_amd64.deb https://s3.amazonaws.com/synthetic-packages/Chromium/deb/chromium-codecs-ffmpeg-extra_73-ubuntu.16.04.1_amd64.deb ;\
dpkg -i chromium-browser_73-ubuntu.16.04.1_amd64.deb chromium-codecs-ffmpeg-extra_73-ubuntu.16.04.1_amd64.deb  ;\
echo "chromium-browser hold" | sudo dpkg --set-selections  ;\
echo "chromium-codecs-ffmpeg-extra hold" | sudo dpkg --set-selections  ;\
apt-get -y install xfonts-cyrillic fonts-arphic-uming ttf-wqy-zenhei fonts-wqy-microhei ttf-wqy-microhei ttf-wqy-zenhei xfonts-wqy fonts-hosny-amiri ;} >> /tmp/install.txt 2>&1

##Installation of OneAgent
{ wget -nv -O oneagent.sh "$TENANT/api/v1/deployment/installer/agent/unix/default/latest?Api-Token=$APITOKEN&arch=x86&flavor=default" ;\
 sh oneagent.sh APP_LOG_CONTENT_ACCESS=1 INFRA_ONLY=0 ;\
 rm oneagent.sh ;}  >> /tmp/install.txt 2>&1 
 
## Installation of Active Gate
{ wget -nv -O activegate.sh "$TENANT/api/v1/deployment/installer/gateway/unix/latest?Api-Token=$APITOKEN&arch=x86&flavor=default" ;\
sh activegate.sh --enable-browser-monitors --enable-synthetic ;\
rm activegate.sh ;}  >> /tmp/install.txt 2>&1 

## Get Bankjobs
docker run -d shinojosa/bankjob:v0.2 >> /tmp/install.txt 2>&1

## Get Polymershop
docker run -d -p 8881:8081 shinojosa/polymershop:start >> /tmp/install.txt 2>&1

# NGINX ReverseProxy for AngularShop mapping 9080 to 80 due problems in Maidenhead Wifi
export PUBLIC_IP=`hostname -i`
mkdir /home/ubuntu/nginx
echo "upstream angular {
  server	$PUBLIC_IP:9080;
} 
server {
  listen		0.0.0.0:80;
  server_name	localhost;
  location / {
    proxy_pass	http://angular;
    }
}" > /home/ubuntu/nginx/angular.conf
docker run -p 80:80 -v /home/ubuntu/nginx:/etc/nginx/conf.d/:ro -d --name nginx nginx

# Install java8
apt install -y default-jre >> /tmp/install.txt 2>&1
 
# Install Easytravel with Angular shop
#  wget -nv -O dynatrace-easytravel-linux-x86_64.jar http://zgz757.managed-sprint.dynalabs.io/dynatrace-easytravel-linux-x86_64-2.0.0.3096.jar
# http://zgz757.managed-sprint.dynalabs.io/dynatrace-easytravel-linux-x86_64-2.0.0.3147.jar 
# http://dexya6d9gs5s.cloudfront.net/latest/dynatrace-easytravel-linux-x86_64.jar
echo "Installing EasyTravel"  >> /tmp/install.txt 2>&1
{ cd /home/ubuntu ;\
 wget -nv -O dynatrace-easytravel-linux-x86_64.jar http://zgz757.managed-sprint.dynalabs.io/dynatrace-easytravel-linux-x86_64-2.0.0.3147.jar ;\
 chmod 777 dynatrace-easytravel-linux-x86_64.jar ;\
 sudo -H -u ubuntu bash -c 'java -jar dynatrace-easytravel-linux-x86_64.jar -y' ;\
 chmod 755 -R easytravel-2.0.0-x64 ;\
 chown ubuntu:ubuntu -R easytravel-2.0.0-x64 ; }  >> /tmp/install.txt 2>&1 

# Configuring EasyTravel Memory Settings, Angular Shop and Weblauncher. 
sed -i 's/apmServerDefault=Classic/apmServerDefault=APM/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.frontendJavaopts=-Xmx160m/config.frontendJavaopts=-Xmx320m/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.backendJavaopts=-Xmx64m/config.backendJavaopts=-Xmx320m/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.autostart=/config.autostart=Standard with REST Service and Angular2 frontend/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.autostartGroup=/config.autostartGroup=UEM/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadB2BRatio=0.1/config.baseLoadB2BRatio=0/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadCustomerRatio=0.25/config.baseLoadCustomerRatio=0.1/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadMobileNativeRatio=0.1/config.baseLoadMobileNativeRatio=0/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadMobileBrowserRatio=0.25/config.baseLoadMobileBrowserRatio=0/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadHotDealServiceRatio=0.25/config.baseLoadHotDealServiceRatio=1/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadIotDevicesRatio=0.1/config.baseLoadIotDevicesRatio=0/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadHeadlessAngularRatio=0.0/config.baseLoadHeadlessAngularRatio=0.25/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.baseLoadHeadlessMobileAngularRatio=0.0/config.baseLoadHeadlessMobileAngularRatio=0.1/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.maximumChromeDrivers=10/config.maximumChromeDrivers=3/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.maximumChromeDriversMobile=10/config.maximumChromeDriversMobile=3/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
sed -i 's/config.reUseChromeDriverFrequency=4/config.reUseChromeDriverFrequency=3/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties

# Deactivate SSL. We dont need it.
sed -i 's/config.apacheWebServerSslPort=9443/config.apacheWebServerSslPort=0/g' /home/ubuntu/easytravel-2.0.0-x64/resources/easyTravelConfig.properties
# Fix SSL issue of the easytravel shop so our DevOps team does not get notified with the automatic scanning
#sed -i 's/SSLProtocol all -SSLv2/SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1/g' /home/ubuntu/.dynaTrace/easyTravel\ 2.0.0/easyTravel/config/httpd.conf
# Fix finding the Java package
#sed -i "s/JAVA_BIN=..\\/jre\\/bin\\/java/JAVA_BIN=\\/usr\\/bin\\/java/g" /home/ubuntu/easytravel-2.0.0-x64/weblauncher/weblauncher.sh

# clean up
rm dynatrace-easytravel-linux-x86_64.jar

# Launch ET as ubuntu otherwise LOTS will fail
cd /home/ubuntu/easytravel-2.0.0-x64/weblauncher/
sudo -H -u ubuntu bash -c 'sh weblauncher.sh > /tmp/weblauncher.log 2>&1 &'

{ [[ -f  /tmp/weblauncher.log ]] && echo "***EasyTravel launched**" || echo "***Problem launching EasyTravel **" ; } >> /tmp/install.txt 2>&1
{ date ; echo "installation done" ;} >> /tmp/install.txt 2>&1 
