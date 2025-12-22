
rule Trojan_Win32_SystemOwnerDiscovery_SB{
	meta:
		description = "Trojan:Win32/SystemOwnerDiscovery.SB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 6f 00 61 00 6d 00 69 00 20 00 3e 00 20 00 } //1 whoami > 
		$a_00_1 = {77 00 68 00 6f 00 61 00 6d 00 69 00 2e 00 65 00 78 00 65 00 20 00 3e 00 20 00 } //1 whoami.exe > 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}