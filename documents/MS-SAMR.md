## Protocol:
[Security Account Manager (SAM) Remote Protocol (MS-SAMR)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)

## Interface UUID: 
* 12345778-1234-ABCD-EF00-0123456789AC

## Server Binary: 
* `samsrv.dll` (loads into) `lsass.exe`

## Endpoint:
* ncacn_ip_tcp
* ncacn_np: `\PIPE\lsass` alias `\pipe\samr`

## ATT&CK Relation:
* [T1136.002 - Domain Account](https://attack.mitre.org/techniques/T1136/002/)
* [T1069.002 - Domain Group](https://attack.mitre.org/techniques/T1069/002/)


## Indicator of Activity (IOA):
* Network: 
  * Network traffic over `\pipe\samr` or `\pipe\lsass`
  * Destination port: 445
  * Methods: 
    * `SamrOpenDomain`
    * `SamrOpenGroup`
    * `SamrLookupNames`
    * `SamrQueryInformationGroup`
    * `SamrEnumerateDomainsInSamServer`
    * `SamrEnumerateGroupsInDomain`
    * `SamrEnumerateAliasesInDomain`
    * `SamrEnumerateUsersInDomain`

* Host:
  * Event ID 5145:
    * Share Name: `\\*\IPC$`
    * Relative Target Name: `samr`
    * Access Mask: `0x12019f` (Rights could be potentially less depending on the method called. Test was done via net.exe)
    * Object Type: `File`
    * Look at Source Address when investigating 


## Prevention Opportunities: 
* Add RestrictRemoteSam in HKLM/System/CurrentControlSet/Control/Lsa to O:SYG:SYD:(A;;RC;;;BA) to only allow Local Admin (on DC)/Remote SAM User Group
  * Tool that does this: https://github.com/shmitty275/powershell/blob/master/SAMRi10.ps1
  
* RPC Filter Example: 
```
rpc
filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=12345778-1234-ABCD-EF00-0123456789AC
add condition field=remote_user_token matchtype=equal data=D:(A;;RC;;;BA)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=e3514235-4b06-11d1-ab04-00c04fc2dcd2
add filter
quit
```
* RPC Filter to only allow local admins to use SAMR 

## Notes: 
* Often seen with BH activity. Look for connection to named pipe (both client and server)
* Server, domain, group, alias and user can be read/read through SAMR. 
* User, group and alias can be created/deleted
* MDI has alert set up that will trigger after first month: https://docs.microsoft.com/en-us/defender-for-identity/reconnaissance-alerts
* If RPC Filter is applied, set up a "Remote SAM Group" and apply them to the filter 


## Useful Resources: 
* https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/
* https://github.com/shmitty275/powershell/blob/master/SAMRi10.ps1
