This document will hold information for both protocols: MS-LSAD & MS-LSAT. MS-LSAT is issued alongside MS-LSAD and leverages the same interface UUID. 

## Protocol:
* [Local Security Authority (Domain Policy) Remote Protocol (MS-LSAD)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc)
* [Local Security Authority (Translation Methods) Remote Protocol (MS-LSAT)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/1ba21e6f-d8a9-462c-9153-4375f2020894)

## Interface UUID: 
* `12345778-1234-ABCD-EF00-0123456789AB`

## Server Binary: 
* `lsarpc.dll` (loads into) `lsass.exe`

## Endpoint:
* ncacn_ip_tcp
* ncacn_np: `\PIPE\lsass` alias `\pipe\lsarpc`

## ATT&CK Relation:
* [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
* [T1069.002 - Domain Group](https://attack.mitre.org/techniques/T1069/002/)

## Indicator of Activity (IOA):
* Network: 
    * Network traffic over: `\pipe\lsarpc` or `\pipe\lsass`
    * Destination port: `445`
  * Methods: 
    * `LsarOpenPolicy*`
    * `LsarLookupSid*`
    * `LsarQueryInformationPolicy*`
    * `LsarSetInformationPolicy*`
    * `LsarEnumerateTrustedDomains`
    * `LsarEnumeratePrivileges`
    * `LsarEnumeratePrivilegesAccount`
    * `LsarEnumerateAccounts`
    * `LsarEnumerateAccountRights`
    * `LsarEnumerateAccountsWithUserRight`
    * `LsarQueryDomainInformationPolicy*`

* Host:
  * Event ID 5145:
    * Share Name: `\\*\IPC$`
    * Relative Target Name: `lsarpc`
    * Access Mask: `0x12019f` (Rights could be potentially less depending on the method called. Test was done via net.exe)
    * Object Type: `File`
    * Look at Source Address when investigating 
    * User account will not be a machine account ($)

* Potentially see a high volume of 5145's due to the number of enumeration requests


## Prevention Opportunities: 
* RPC Filter Example: 
```
rpc
filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=12345778-1234-ABCD-EF00-0123456789AB
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;BA)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=12345778-1234-ABCD-EF00-0123456789AB
add filter
quit
```

* Filter forces the interface `12345778-1234-ABCD-EF00-0123456789AB` to only accept calls coming from a local admin on the host (BA in the SDDL string).

## Notes: 
* Can be seen with enumeration activity.
* By default domain users can query this information via: dsacls.exe "cn=users,dc=marvel,dc=local"
* Created a RPC filter to only allow BA's (local admins) to perform this action, but note during testing it seemed that legitimate connections over these protocols were occurring. Unsure of the repercussions limiting the access to this protocol will cause. Could create a group that has BAs and Machine accounts, then apply that group SID to the filter. 


## Useful Resources: 
* https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaqueryinformationpolicy
