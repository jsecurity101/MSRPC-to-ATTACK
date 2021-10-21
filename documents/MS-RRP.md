## Protocol:
* [Remote Registry (MS-RRP)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78)

## Interface UUID: 
* `338CD001-2244-31F1-AAAA-900038001003`

## Server Binary: 
* `regsvc.dll` (loads into) `svchost.exe`

## Endpoint:
* ncacn_np: `\PIPE\winreg`

## ATT&CK Relation:
* [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/) 
* [T1012 - Query Registry](https://attack.mitre.org/techniques/T1012/)


## Indicator of Activity (IOA):
* Network: 
  * Methods: 
    * `BaseRegCreateKey`
    * `BaseRegQueryInfoKey`
    * `BaseRegSetValue`
* Host: 
  * Inbound network connection to: System over `\pipe\winreg`
  * Registry key modifications
    * Sysmon Event ID 12/13
  * Native windows binary to interact with registry remotely: reg.exe (look for ADD/QUERY parameters)
    * Process creation events
  * Remote Registry Service start type changed

## Prevention Opportunities: 
* Turn off the remote registry service and disable it.
* Modify permissions on sensitive registry keys

RPC Filter Example:
```
rpc
filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=338CD001-2244-31F1-AAAA-900038001003
add condition field=remote_user_token matchtype=equal data=D:(A;;KA;;;DA)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=367ABB81-9844-35F1-AD32-98F038001003
add filter
quit
```

## Notes: 
* By default local administrators can start the remote registry service and interact with the registry remotely. 

* If remote registry is an operational need, create a group specific to this action. Apply changes to the registry/rpc filter. 


## Useful Resources: 
*  https://car.mitre.org/analytics/CAR-2014-11-005/