## Protocol:
* [Netlogon Remote Protocol - (NRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f)

## Interface UUID: 
* 12345678-1234-ABCD-EF00-01234567CFFB

## Server Binary: 
* netlogon.dll (loads into) lsass.exe

## Endpoint:
* ncacn_ip_tcp
* ncacn_np: `\PIPE\netlogon` alias `\pipe\lsass`

## ATT&CK Relation:
* Netlogon Elevation of Privilege Vulnerability (Zerologon)
* [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)


## Indicator of Activity (IOA):
* Network: 
  * Method (either over TCP or named pipe - netlogon): 
    *  NetrServerAuthenticate2/3 (high volume)
    *  NetrServerPasswordSet2
    *  NetrServerReqChallenge (high volume)
    *  NetrLogonSamLogonWithFlags 
    *  DRS Methods (DrsGetNCChanges) (Zerologon attack specific)

* Host: 
  * Window Security Event - 4624
    *  Anonymous Logon or DC Computer Account
    *  Logon Type 3
    *  Auth Package: NTLM
    *  Logon Process: NtLmSsp
    *  Source Network Address & Workstation Name will show source
    *  Logon ID tie to other events (4742)

  * Window Security Event - 4742:
    *  Look for password last set on DCs
    *  Account Name is DC Machine Account
    *  Security ID - same as 4624

  *  Tie Logon ID to 4624 


## Prevention Opportunities: 
* Microsoft Patch: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1472

RPC Filter: 
```
rpc
filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=12345678-1234-abcd-ef00-01234567cffb
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DC)
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;AU)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=12345678-1234-abcd-ef00-01234567cffb
add filter
quit
```
* Still need to apply patch from Microsoft, but this filter will remove the ability for non-domain joined computers & unauthenticated users from using this interface. 
* Being that Netlogon is a service, unsure of the impacts if the filter were changed to only allow domain computers and domain admins. 
* If NTLM isn't allowed in organization, this filter might be a better alternative: 


```
rpc
filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=12345678-1234-abcd-ef00-01234567cffb
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DC)
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;AU)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=12345678-1234-abcd-ef00-01234567cffb
add filter
quit
```

## Notes: 

### Known Threats: 
* Zerologon
  * Netlogon calls are not encrypted
    * Caused by an attacker forcing SMB fallback right after the machine performed authentication handshake, in turn disabling force encryption.
    * Done by injecting TCP RST packets when the client attempts to connect to port 135 or the dynamic Netlogon port,
    * Attacker could replace a logon failed with a logon success message, giving access to DC.


## Useful Resources: 
*  https://www.secura.com/uploads/whitepapers/Zerologon.pdf
*  https://dirkjanm.io/a-different-way-of-abusing-zerologon/
*  https://www.kroll.com/en/insights/publications/cyber/cve-2020-1472-zerologon-exploit-detection-cheat-sheet
