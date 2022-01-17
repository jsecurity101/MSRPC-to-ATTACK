## Protocol:
* [File Server Remote VSS Protocol - MS-FSRVP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/67f0fdd9-d8bc-445d-95de-2cb6d5c4d149)

## Interface UUID: 
* `a8e0653c-2744-4389-a61d-7373df8b2292`

## Server Binary: 
`fssagent.dll` loads into `svchost.exe`

## Endpoint:
* ncacn_np: `\\pipe\FssagentRpc`

## ATT&CK Relation:
* [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)
* [T1557 - LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
* [ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)

## Indicator of Activity (IOA):
* Network: 
  - NTLM Authentication requests (zeek - ntlm.log)

* RPC Methods: 
  * IsPathSupported
  * IsPathShadowCopied
  
* Host: 
  - Inbound connection over port 445 to `System` process (WSE - 5156 + Sysmon - 3)
  - Pipe connection `\FssagentRpc` from `System` process  (Sysmon - 18)
  - fssagent.dll loaded into svchost.exe (Sysmon -7)
  - LogonEvent
      - LogonType: `3`
      - Elevated Token: `Yes`
      - Account Name: <Domain User>
      - LogonProcess: `NtlmSsp`
      - Auth Package: `NTLM`
  - Network Share Event:
      - Account Name: <Domain User> (same logon id as logon event)
      - Object Type: File
      - Share Name `\\*\IPC$`
      - Relative Target Name: `FssagentRpc`
      - AccessMask: `0x3`
      - Accesses:
          - `ReadData (or ListDirectory)`
          - `WriteData (or AddFile)`
## Prevention Opportunities: 
*  Turn off fssagent Service
*  Set fssagent Service Startup Type to Disabled   
* Certificate Mitigation: https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/07/microsoft-provides-more-mitigation-instructions-for-the-petitpotam-attack/
* Disable NTLM Authentication
* RPC Filters
    ```
    rpc
    filter
    add rule layer=um actiontype=permit
    add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
    add condition field=auth_type matchtype=equal data=16
    add condition field=auth_level matchtype=equal data=6
    add filter
    add rule layer=um actiontype=block
    add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
    add filter
    quit
    ```

  * When set this will not relay NTLM auth. 

  * Another option is to block the interface altogether or specify the domain group allowed to request this information: 

    ```
    rpc
    filter
    add rule layer=um actiontype=permit
    add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
    add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
    add filter
    add rule layer=um actiontype=block
    add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
    add filter
    quit
    ```

## Notes: 



## Useful Resources: 
Credit to [Lionel Gilles](https://twitter.com/topotam77) for introducing this attack and [Charlie Bromberg](https://twitter.com/_nwodtuhs) for POC. 


* https://pentestlaboratories.com/2022/01/11/shadowcoerce/
* https://www.tiraniddo.dev/2021/08/how-windows-firewall-rpc-filter-works.html
* https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp