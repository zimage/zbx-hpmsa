# zbx-hpmsa
Zabbix module for monitor HPE MSA storages via XML API.  
Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api  
Also you can contact me with Telegram: @asand3r

zbx-hpmsa provides possibility to make Low Level Discovery of HPE MSA storage components via it's XML API. Also it can get health status of discovered component.  
Program wrote with Python 3.6, but works with Python 3.4 from CentOS (I didn't check it with earlier versions, sorry).  

**Latest stable version:** 0.4

__Please, read 'Requirements and Installation' section in Wiki before use.__  

## Dependencies
 - requests
 - sqlite3

## Feautres  
**Common:**
 - [x] Bulk requests for dependent items (Zabbix 3.4+)
 - [x] HTTPS support
 - [x] Login cache (SQLite3)

**Low Level Discovery:**
 - [x] physical disks 
 - [x] virtual disks
 - [x] controllers
 - [x] Enclosures

**Component status:**
 - [x] physical disks 
 - [x] virtual disks
 - [x] controllers
 - [x] Enclosures

## TODO  
- [ ] Add correct processing of round-robin DNS records

## Supported arguments  
**-m|--msa**  
HPE MSA DNS name or IP address.  
**-u|--user**  
Sets MSA username  
**-p|--password**  
Sets password for MSA user  
**-f|--loginfile**  
Path to file with login and password data  
**-d|--discovery**  
Enables discovery mode.  
**-c|--component**  
Sets component to request.  
**-g|--get|--health**  
Get component health status.  
**-v|--version**  
Print script version and exit.  
**--https [verify|direct]**  
Using HTTPS instead HTTP.  
**--showcache**  
Print cache content and exit.


## Usage
You can find more examples on Wiki page, but I placed some cases here too.  
- LLD of enclosures, controllers, virtual disks and physical disks:
```bash
[user@server ~] # ./zbx-hpmsa.py --discovery --msa MSA-NAME-OR-IP --component vdisks

{"data":[{"{#VDISKNAME}":"vDisk01"},{"{#VDISKNAME}":"vDisk02"}]}
```
- Request health status of one component. E.g. disk '1.1':
```bash
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get 1.1

OK
```
- Bulk request to get all available data. E.g. all disks or controller 'A':
```bash
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get all
{"1.1":{"health":"OK","temperature":"25","work_hours":"21170"},"1.2":{"health":"OK","temperature":"24","work_hours":"21168"}, ...}
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component controllers --get all
{"A":{"health":"OK","cf_health":"OK","ports":{"A1":{"health":"OK","status":"Up","sfp_status":"OK"},"A2":{"health":"OK","status":"Up","sfp_status":"OK"},"A3":{"health":"N/A","status":"Disconnected","sfp_status":"Not present"},"A4":{"health":"N/A","status":"Disconnected","sfp_status":"Not present"}}},"B":{"health":"OK","cf_health":"OK","ports":{"B1":{"health":"OK","status":"Up","sfp_status":"OK"},"B2":{"health":"OK","status":"Up","sfp_status":"OK"},"B3":{"health":"N/A","status":"Disconnected","sfp_status":"Not present"},"B4":{"health":"N/A","status":"Disconnected","sfp_status":"Not present"}}}}
```

## Zabbix templates
In addition I've attached preconfigured Zabbix Template here, so you can use it in your environment. It's using Low Level Discovery functionality
and {HOST.CONN} macro to determine HTTP connection URL, so make sure that it points to right DNS name or IP. This template expects what your MSA storage has default user with default password - **'monitor'@'!monitor'**, but if it isn't true - correct it with '-u' and '-p' options. Also it using HTTP and you must enable it or add '--https' to each script call in the template. You can check it it command line:
```bash 
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get all --user FOO --password BAR
```  
Have fun and rate it on [share.zabbix.com](https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api) if you like it. =)

**Tested with**:  
HP MSA P2000 G3, HP MSA 2040, HP MSA 2050

**Known Issues**:
- Sometimes appears the error "The user is not recognized on this system" though username and password are correct.
  - Fixed in 0.2.5.2 and higher.  
- Using '--https verify' with dns round-robin doesn't works correctly. It may give you the "ERROR: -10027", that means the user in not recongnized on the system. It happens because of session key was given from one MSA controller, but the script tries to establish connections the other one. The option '--https direct' will works fine, so you can try to use it instead. I haven't full solution right now, so just don't using it so. =)
- LLD rule of enclosures and controllers can show the next error: __"ERROR: Cannot create item: item with same key 'item.key' already exists."__
It's because of JSON file forming incorrect, but all items creating successfully. LLD code was corrected in v0.3.3.1 and v0.4.
