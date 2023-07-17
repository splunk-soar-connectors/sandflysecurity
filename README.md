[comment]: # "Auto-generated SOAR connector documentation"
# Sandfly Security

Publisher: Sandfly Security, Ltd.  
Connector Version: 1.4.0  
Product Vendor: Sandfly Security  
Product Name: Sandfly Security Agentless Linux Security  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

Sandfly Security app to gather information, initiate system scans and other actions on the Sandfly Server

[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "Copyright (c) Sandfly Security, Ltd., 2023"
[comment]: # ""
[comment]: # "This unpublished material is proprietary to Recorded Future. All"
[comment]: # "rights reserved. The methods and techniques described herein are"
[comment]: # "considered trade secrets and/or confidential. Reproduction or"
[comment]: # "distribution, in whole or in part, is forbidden except by express"
[comment]: # "written permission of Sandfly Security."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Authentication

You must have an active Sandfly Security account in order to trigger actions. The account must also
have an active license with the Splunk Connector feature activated. The configuration below will
require your Sandfly Security Server portal URL and a username and password that can trigger the
actions or retrieve the information.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Sandfly Security server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Sandfly Security Agentless Linux Security asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**Sandfly Server URL** |  required  | string | Sandfly Server URL
**Username** |  required  | string | Login Username
**Password** |  required  | password | Login Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[scan host](#action-scan-host) - Run a Sandfly investigation  
[sandfly full investigation](#action-sandfly-full-investigation) - Run a full Sandfly investigation  
[sandfly process investigation](#action-sandfly-process-investigation) - Run a Sandfly process investigation  
[sandfly file investigation](#action-sandfly-file-investigation) - Run a Sandfly file investigation  
[sandfly directory investigation](#action-sandfly-directory-investigation) - Run a Sandfly directory investigation  
[sandfly log tamper investigation](#action-sandfly-log-tamper-investigation) - Run a Sandfly log tamper investigation  
[sandfly user investigation](#action-sandfly-user-investigation) - Run a Sandfly user investigation  
[sandfly recon investigation](#action-sandfly-recon-investigation) - Run a Sandfly recon investigation  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[get system info](#action-get-system-info) - Get information about an endpoint  
[list users](#action-list-users) - List the user accounts on a machine  
[list processes](#action-list-processes) - List the running processes on a machine  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'scan host'
Run a Sandfly investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target host for the selected types.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or name of the host | string | 
**directory** |  optional  | Sandfly Type - directory | boolean | 
**file** |  optional  | Sandfly Type - file | boolean | 
**incident** |  optional  | Sandfly Type - incident | boolean | 
**log** |  optional  | Sandfly Type - log | boolean | 
**policy** |  optional  | Sandfly Type - policy | boolean | 
**process** |  optional  | Sandfly Type - process | boolean | 
**recon** |  optional  | Sandfly Type - recon | boolean | 
**user** |  optional  | Sandfly Type - user | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.directory | boolean |  |  
action_result.parameter.file | boolean |  |  
action_result.parameter.incident | boolean |  |  
action_result.parameter.ip_hostname | string |  |  
action_result.parameter.log | boolean |  |  
action_result.parameter.policy | boolean |  |  
action_result.parameter.process | boolean |  |  
action_result.parameter.recon | boolean |  |  
action_result.parameter.user | boolean |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly full investigation'
Run a full Sandfly investigation

Type: **investigate**  
Read only: **False**

Run a full Sandfly investigation for all process, file, directory, log, user, incident, policy and recon types.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly process investigation'
Run a Sandfly process investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target system for the process type.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname of the target system | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly file investigation'
Run a Sandfly file investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target system for the file type.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname of the target system | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly directory investigation'
Run a Sandfly directory investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target system for the directory type.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname of the target system | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly log tamper investigation'
Run a Sandfly log tamper investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target system for the log type.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname of the target system | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly user investigation'
Run a Sandfly user investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target system for the user type.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname of the target system | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'sandfly recon investigation'
Run a Sandfly recon investigation

Type: **investigate**  
Read only: **False**

Run a Sandfly investigation against the target system for the recon type.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | IP or Hostname of the target system | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get system info'
Get information about an endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | Hostname/IP address to get info of | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  `host name`  `ip`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'list users'
List the user accounts on a machine

Type: **investigate**  
Read only: **True**

List all user accounts on the specified system.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | Hostname/IP of the machine to list user accounts | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |  
action_result.status | string |  |   success  failed 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'list processes'
List the running processes on a machine

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | Hostname/IP of the machine to list processes on | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  