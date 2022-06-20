## Protocol:
* [Distributed File System (DFS): Namespace Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/a7ecdbe0-c138-471d-85b6-a474825da9eb)

## Interface UUID: 
* `4FC742E0-4A10-11CF-8273-00AA004AE673`

## Server Binary: 
* `dfssvc.exe` (On Domain Controller)

## Endpoint:
* ncacn_np: `\\pipe\netdfs`

## ATT&CK Relation:
* [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)


## Indicator of Activity (IOA):
* Network: 
  * Inbound network connection over port 445 to the `System` Process (PID=4)
  * Connection over pipe `netdfs`

  * Methods: 
    * `NetrDfsRemoveStdRoot` (potentially more, only tested method)

* Host: 
    * (Server Side):
        * Event ID 5156
         * Account Name: domain user
         *  Object Type: `File`
         *  Share Name: `\\*\IPC$`
         *  Relative Target Name: `netdfs`
         *  Access Mask:  `0x12019F`
         * Source Address: Address of where request is coming from. Good for context during investigation. 
         *  Accesses:
              *  `ReadData (or ListDirectory)`
              * ` WriteData (or AddFile)`

        * Event ID 4624
          *  Logon Type: `3`
          *  Account Name: domain user
          *  Process ID: `0x0`
          *  Elevated Token: `Yes`
          *  Authentication Package: NTLM (by defualt of PoC, subject to change and could be Kerberos)

    * Join on LogonID for queries. 

## Prevention Opportunities: 
* RPC Filter: 
    * Example: 

        ```
        rpc
        filter
        add rule layer=um actiontype=permit
        add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
        add condition field=auth_type matchtype=equal data=16
        add condition field=auth_level matchtype=equal data=6
        add filter
        add rule layer=um actiontype=block
        add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
        add filter
        quit
        ``` 
    * This filter will only allow connections through `4FC742E0-4A10-11CF-8273-00AA004AE673` if the authentication type is `Kerberos (16)` and the authentication type is `RPC_C_AUTHN_LEVEL_PKT_PRIVACY (6)`. This is going to prevent NTLM from being used and inturn relay from being performed. 

* Disable NTLM Authentication
* Enable SMB signing
*  MSFT Suggestions: https://support.microsoft.com/en-gb/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429

## Notes: 
* The `Dfs` Service is running by default on Domain Controllers, so it might break functionality to turn this service off or disable it. 


## Useful Resources: 
PoC: https://github.com/Wh04m1001/DFSCoerce