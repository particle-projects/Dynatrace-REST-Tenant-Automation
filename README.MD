> **DISCLAIMER**: This project was developed for educational purpouses only and is not complete, nor supported. It's publishment is only intended for helping others automate environments for delivering workshops with Dynatrace.

# 🤖Dynatrace RTA 🔃- REST Tenant Automation

#### Spend more time innovating and less time configuring

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

pip install -r requirements.txt
```

After you have installed them, just run `py rta.py help` for printing out the help.

![](doc/rta_help.png)

Before running any action is highly recommended that you run the `validate` function so you see the output of the configuration and the entries that will be executed in the CSV file.  

`python3 rta.py validate`



## How does it work?

The `config.json` file:

about the status of the action as well as the id of the tenant, usergroup tenant token, ec2 instanceId, ec2 public dns, etc..<br />The file allows also other custom rows and will not modify them. when rewriting.


```bash
====== [RTA] Rest Tenant Automation Configuration ======
cmc:
 |-cmc_url             : https://xxxxx.dynatrace-managed.com The url of the cluster (when using Managed) with no leading slash
 |-cmc_token           : XXXXYYYYYZZZZ      The API Token of the Cluster. Needed for creating tenants.

csv_dir   : csv					The csv directory to read/write files.
csv_file  : attendees.csv		The file to read for the actions called.
log_dir   : log					The log dir 
log_file  : rta.log				The log file
ssh:
 |-ssh_dir             : ssh		The SSH dir
 |-cmd_file            : cmd.sh		The shell file containing the commands to execute

aws:
 |-aws_dir             : aws			The AWS directory
 |-aws_config          : instance.json	The AWS configuration for creating EC2

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
 |-set_up_env          : True			Sets up the environment (See def set_up_environment(data) )

action_remove:
 |-deactivate_tenant   : True			Deactivates the tenant (managed)
 |-remove_tenant       : True			Removes the tenant (managed)
 |-delete_user_group   : True			Deletes the user group (managed)
 |-delete_user         : True			Deletes the user
 |-delete_ec2_instance : True			Terminates the EC2 instance
```


## Tenant configuration

Each tenant will end up with its own tenant preconfigured. For expanding the configuration of the tenant take a look at the function *set_up_environment*. This will set up a custom dashboard ponting out to the deployed applications and resources for the session, a custom dashboard, a synthetic test etc.. l. For modifying the template like the dashboard just go to the skel directory and modify the dashboard.json file. 

![](doc/custom-dashboard.png)



## Templates

The templates are in the **skel** directory. 

To validate and print the config and the users with their control flags type: 

```bash
py cmc.py validate
```

## Control Flags

**skip** = empty and "false" equals false. Meaning the actions defined in the program (command and config file) will be applied to that user. If it contains True then the user will be skipped.

**isClusterAdminGroup** =  empty and "false" equals false. True will set the user_group for the user to cluster_admin. This user will have access to the CMC and to all tenants.


## CSV Fields (mandatory and optional for Managed and SaaS)

The CSV is a semicolon ; separated file.

The order of the fields is not important nevertheless the program will keep the order when rewriting the results of the actions created. The keys are case sensitive.

| Key                 | Mandatory | default Value            | Description                                                              |
| ------------------- | --------- | ------------------------ | ------------------------------------------------------------------------ |
| email               | yes       |                          | the email of the person                                                  |
| firstName           | yes       |                          | the firstname                                                            |
| lastName            | yes       |                          | the lastname                                                             |
| tenantId            | no        | firstName-LastName       | if found in the CSV file can be overwritten                              |
| groupId             | no        | firstName-LastName-group |                                                                          |
| skip                | no        | FALSE                    | If found and if "true", the row will be skipped                          |
| isClusterAdminGroup | no        | FALSE                    | If found and if "true", the userGroup will be added as an cluster admin. |



## AWS Account

The program uses boto3, which is a library for managing aws resources. This will work automatically if you have AWS cli set up in your environment so you dont have to code it or enter it everytime.

[Here is how to set up your environment credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

You can set them [programatically](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html), but I strongly advice to set them in your environment. Be aware that the AMI instance IDs difer from one region to another, meaning an ubuntu has a different AMI ID for "Europe West" than "Europe East". 

## AWS concurrent running instances limit:

By default AWS has a limit of 20 multiple instances running. You might want to check up that limit in the region before creating the EC2 instances.


## How to collaborate

Create branch with the improvement and a pull request. A tip to not forget pushin configuration is marking configuration files in your local repository not to be tracked. You can acomplish this by typing the following git command:
`git update-index --assume-unchanged config.json`


## Ideas for Improvement

- Document the flow of the program.
- make a more generic template to add more actions

## Author
sergio.hinojosa@dynatrace.com
