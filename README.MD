> **DISCLAIMER**: This project was developed for educational purpouses only and is not complete, nor supported. It's publishment is only intended for helping others automate environments for delivering workshops with Dynatrace.

# 🤖Dynatrace RTA 🔃- REST Tenant Automation

> ## ***🥼⚗ Spend more time innovating and less time configuring***

Python program that creates and automates environments via the Dynatrace API. This small program reads a CSV file and will execute for each entry the command called (or a sequence of commands). Each entry in the CSV file can be controled via flags `skiped=true` as well as the subcommands. The subcommands of the actions `create`, `remove` and `test` can be controled via flags defined in the `config.json` file. This program can work with a Managed Cluster and SaaS environments. 

The program will log the results and write it in the CSV when needed, like if it creates an EC2 instance it will write the `instance-Id`, the `public DNS` and `IP`.

This programm is very powerful for creating and automating environments for workshops. It will set-up an environment as defined with everything preconfigured such as custom dashboards linking them to the user-interface of the deployed applications of the created EC2 machines bein monitored by the OneAgent, ManagementZones, Request-Attributes, Application-Rules and it's definitions. 

#### 🦸‍♂️The Motivation and 💡 idea behind this, is that the 👨‍🎓 student gets everything configured so he spends **more time learning Dynatrace** and not configuring other things trivial to the Topic to learn.

## Overview of a sample workshop setup

![](doc/rta_diagramm.gif)

## Prerequisites

- [python 3](https://www.python.org/downloads/)

- [A Dynatrace Tenant](https://www.dynatrace.com/trial/?gclid=Cj0KCQiAqNPyBRCjARIsAKA-WFzFj8-YaXYjzaY7uVGj0klG2KnGTs2WaQ8Wg3AI_Z8dX2Fzy9-fOy4aAu5IEALw_wcB)

- AWS account 
  
  > (optional for the ec2-actions) the program (boto3) will look into your `.aws` file for credentials. [Here you can get a free account](https://aws.amazon.com/free/)

## Features in a Nutshell

```properties
- Create environments with user and user_groups (Managed)
- Configure Dynatrace environments 
	- Create customized Dashboards for single users
	- Configure Applications and AppRules
	- Auto Tagging rules
	- Management Zones
	- Request Attributes
	- Custom Services
- Connect and execute commands via SSH 
- Enable EasyTravel problem patterns via REST
- Read and write entries in a CSV file
- Write results in JSON format
- Write action results back in the CSV file
	- results of the actions called
	- tenantId
	- ec2 instance id / publicIp / dns
	- tenant token
	- others...
- Logging
- Create an EC2 Instance with custom deployment 🔗 linked to each tenant
	- OneAgent bound to the tenant
  	- EasyTravel (8080/8079), Admin Console (8094) and Angular (9080) configured
- Remove the EC2 Instance and deactivate and remove the tenant.
- Manage the execution with commands via Control RowFlags (true/false) for each row:
	- skip - Skip the row for the actions
  	- isClusterAdmin - to add the User as a cluster admin
- Validate function to read the configuration and print the users in the CSV file. 
```

## Installing RTA

This commands will get you python, pip and the dependencies installed in your system.
```bash
sudo apt install python3

sudo apt install python3-pip

pip3 install -r requirements.txt
```

After you have installed them, just run `python3 rta.py help` for printing out the help.

![](doc/py_rta_help.png)

Before running any action is highly recommended that you run the `validate` function so you see the output of the configuration and the entries that will be executed in the CSV file.  

`python3 rta.py validate`

## How does it work?

The `config.json` file:

about the status of the action as well as the id of the tenant, usergroup tenant token, ec2 instanceId, ec2 public dns, etc..

The file allows also other custom rows and will not modify them. when rewriting.


```bash
====== [RTA] Rest Tenant Automation Configuration ======
cmc:
 |-cmc_url     : https://xxxxx.dynatrace-managed.com 	The url of the cluster (when using Managed) with no leading slash
 |-cmc_token   : XXXXYYYYYZZZZ     		 	The API Token of the Cluster. Needed for creating tenants.

csv_dir   : csv					The csv directory to read/write files.
csv_file  : attendees.csv			The file to read for the actions called.
log_dir   : log					The log dir 
log_file  : rta.log				The log file
ssh:
 |-ssh_dir             : ssh		The SSH dir
 |-cmd_file            : cmd.sh		The shell file containing the commands to execute

aws:
 |-aws_dir             : aws			The AWS directory
 |-aws_config          : instance.json		The AWS configuration for creating EC2

action_test:
 |-tenant_api          : True			Will validate the tenant API with the apiToken
 |-ssh_connection      : True			Will validate the SSH connection
 |-easytravel_ping     : True			Will ping the REST Services of EasyTravel

action_create:
 |-create_tenant       : True			Will create the tenant on the Managed Cluster
 |-create_user_group   : True			Will create the userGroup (managed)
 |-create_user         : True			Will create the user (managed)
 |-create_allinone_token: True			Will create a paas and api token (managed/saas)
 |-create_ec2_instance : True			Will create an EC2 and install OneAgent
 |-fetch_ec2_instance  : True			Fetches the DNS/public IP of the EC2
 |-set_up_env          : True			Sets up the environment (See def set_up_environment(data))

action_remove:
 |-deactivate_tenant   : True			Deactivates the tenant (managed)
 |-remove_tenant       : True			Removes the tenant (managed)
 |-delete_user_group   : True			Deletes the user group (managed)
 |-delete_user         : True			Deletes the user
 |-delete_ec2_instance : True			Terminates the EC2 instance
```



## Environment creation

The enviroment creation applies only for Managed instances and consists of the actions `create_tenant` , `create_user_group`, `create_user` and `create_allinonetoken`. The tenant name is the `firstName` and the `lastName` of the attendee.  The JSON definitions (templates) can be found in the `skel` directory. 

## Environment configuration

In the function `set_up_environment` a tenant will be configured via the [Dynatrace Environment API](https://www.dynatrace.com/support/help/extend-dynatrace/dynatrace-api/) . A series of JSON definitions will be imported through different endpoints. The set-up of the environment is optimized for [EasyTravel](https://community.dynatrace.com/community/display/DL/easyTravel) defining two applications, EasyTravel Classic (`application-1.json`) and EasyTravel Angular (`application-2.json`) and its application rules ate in the folder  `apprules`. The other folders found inside the easytravel folder: `autotagging`, `customservices`, `dashboards`, `managementzones`,  `frequentissues`and  `requestattributes` work with the dragndrop principle. All the JSON definitions found in each folder will be configured in the environment for the respective API endpoint..  

### Custom Dashboard

The depicted dashboard below  `dashboard.json` is customized for each environment. With a basic string replacement before posting the Dashboard on the API the attendees will get a highly customized Dashboard. The idea behind this is to deliver a good customer experience and optimize the flow of the class so that every resource that the user needs is placed in the dashboard such as:

- The credentials and information to log-in to their own EC2 instance
- Links to the applications deployed on the EC2 instance (EasyTravel Angular and Classic) 
- Link to a [live help plattform](https://etherpad.org/) deployed in a masters server, where the users can collaborate, chat and get help.
- Agenda 
- Links to the Repository
- Link to any other needed resource (inside and outside of the Dynatrace tenant)

> for modifying the string replacement of the custom dashboard take a look at the `def environment_create_dashboards`

![](doc/dashboard.png)



## Control Flags

You can easily control for which entry to execute the actions called. You can controll this with the column `skip`

**skip** = empty and `false` equals `false`. Meaning the actions defined in the program (command and `config.json`) will be applied to that user. If it contains `True` then the user will be skipped.

**isClusterAdminGroup** = empty and `false` equals `false`. True will set the user_group for the user to cluster_admin in the creation of the environment. This user will have access to the CMC and to all tenants. This only applies for Managed.


## The CSV File (mandatory and optional fields for Managed and SaaS)

- ***The CSV is a semicolon ; separated file.***
- The **keys** are case **sensitive**
- The order of the fields is not important
- The program will keep the order when rewriting the results of the actions created. 
- The CSV may include as many other columns/key as necessary. 

After calling an action, rows with the result of the action will be added to the CSV file. For redundancy (for example if the CSV is opened in Excel or another program and can't be written) inside the `temp` folder a copy of the CSV file with the results will be written. The files will have as name the timestamp and `error` as prefix if an error occurred.  

| Key                 | Mandatory | default Value     | Description                                                  |
| ------------------- | --------- | ----------------- | ------------------------------------------------------------ |
| email               | yes       |                   | the Email of the person                                      |
| firstName           | yes       |                   | the firstname of the person (part of the tenant name)        |
| lastName            | yes       |                   | the lastname of the person (part of the tenant name)         |
| tenantId            | no        | will be generated | applies only for Managed                                     |
| skip                | no        | FALSE             | If found and if "true", the row will be skipped              |
| isClusterAdminGroup | no        | FALSE             | If found and if "true", the userGroup will be added as an cluster admin. |
| tenantId            | generated |                   | the tenantId for Managed                                     |
| tenantUrl           | yes       | generated         | for Managed it will be generated, for SaaS is mandatory with https protocol and no leading slash |
| tokenMmgt           | generated |                   | when creating an environment is the token for creation of API and PaaS tokens |
| apiToken            | yes       | generated         | for Managed it will be generated, for SaaS is mandatory when talking to the API. |
| paasToken           | yes       | generated         | for Managed it will be generated, for SaaS is mandatory when creating an EC2 instance where the OneAgent (or ActiveGate) should be installed. |
| publicDnsName       | no        |                   | when creating an EC2 instance this will be fetched.          |
| publicIpAddress     | no        |                   | when creating an EC2 instance this will be fetched.          |
| sshUser             | no        |                   | a DNS or IP address is needed.  The user for trying to connect via SSH (port 22) and execute remote commands |
| sshPassword         | no        |                   | a DNS or IP address is needed.  The password for trying to connect via SSH (port 22) and execute remote commands. Execute as `sudo` is also possible. |



## AWS 
The configuration of AWS is defined in a folder and in a JSON file specified in the `config.json` properties. In there you specify in which AWS region to create resources and the instance details for the creation.

### AWS Credentials
The program uses boto3, which is a library for managing aws resources. This will work automatically if you have AWS cli set up in your environment so you don't have to code it or enter it everytime.
[Here is how to set up your environment credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
You can set them [programatically](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html), but I strongly advice to set them in your environment. 

### Creating Elastic Cloud Compute instances (EC2):

Be aware that the AMI instance IDs differ from one region to another, meaning an ubuntu has a different AMI ID for "Europe West" than "Europe East". 

```python
def customize_tags(tags, toReplace):
```
By default AWS has a limit of 20 multiple instances running. You might want to check up that limit in the region if you want to instantiate more than 20 ec2's.

## ✅Tips from the Field

### Improving performance
If you want to create multiple environments with their respective EC2's a the same time, I highly recommend to do it in two separate runs since the action `fetch_ec2_instance` and `set_up_env` depends on the creation of the `create_ec2_instance`and waits until a public IP has been assigned to the instance. This can take a couple of seconds for each instance but waiting for 50+ may take multiple minutes. You can drastically reduce this if in the 1st run you execute the following actions: 

```properties
"create_tenant": true,
"create_user_group": true,
"create_user": true,
"create_allinone_token": true,
"create_ec2_instance": true,
```
and in the 2nd you execute the last two (fetch the public IP and set_up the environments). You can easily control this with the action control flags.

```properties
"fetch_ec2_instance": true,
"set_up_env": true
```


## How to collaborate

Do your changes/improvements and create a pull request. A tip for not forgetting pushing private configuration including tokens is marking those configuration files in your local repository not to be tracked. You can acomplish this by typing the following git command:
```bash
git update-index --assume-unchanged config.json
```



## Author
sergio.hinojosa@dynatrace.com
