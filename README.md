[comment]: # "Auto-generated SOAR connector documentation"
# Sandfly Security

Publisher: Sandfly Security, Ltd\.  
Connector Version: 1\.0\.1  
Product Vendor: Sandfly Security  
Product Name: Sandfly Security Agentless Linux Security  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

Sandfly Security app to trigger system scans and other actions on the Sandfly Server


## Authentication

You must have an active Sandfly Security account in order to trigger actions. The account must also
have an active license with the Splunk Connector feature activated. The configuration below will
require your Sandfly Security Server portal URL and a username and password that can trigger the
actions or retrieve the information.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Cisco Umbrella server. Below are the
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
[scan host](#action-scan-host) - Trigger a scan of the specified host  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'scan host'
Trigger a scan of the specified host

Type: **investigate**  
Read only: **False**

Send a request to the Sandfly Server to trigger a scan of the specified host\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | IP or name of the host | string | 
**directory** |  optional  | Sandfly Type \- directory | boolean | 
**file** |  optional  | Sandfly Type \- file | boolean | 
**incident** |  optional  | Sandfly Type \- incident | boolean | 
**log** |  optional  | Sandfly Type \- log | boolean | 
**policy** |  optional  | Sandfly Type \- policy | boolean | 
**process** |  optional  | Sandfly Type \- process | boolean | 
**recon** |  optional  | Sandfly Type \- recon | boolean | 
**user** |  optional  | Sandfly Type \- user | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.parameter\.ip\_hostname | string |  |  
action\_result\.parameter\.directory | boolean |  |  
action\_result\.parameter\.file | boolean |  |  
action\_result\.parameter\.incident | boolean |  |  
action\_result\.parameter\.log | boolean |  |  
action\_result\.parameter\.policy | boolean |  |  
action\_result\.parameter\.process | boolean |  |  
action\_result\.parameter\.recon | boolean |  |  
action\_result\.parameter\.user | boolean |  |  
action\_result\.data | string |  |  
action\_result\.status | string |  |   success  failed 
action\_result\.message | string |  |  
summary\.total\_objects | numeric |  |  
summary\.total\_objects\_successful | numeric |  |  