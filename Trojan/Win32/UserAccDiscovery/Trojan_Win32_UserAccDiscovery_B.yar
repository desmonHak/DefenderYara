
rule Trojan_Win32_UserAccDiscovery_B{
	meta:
		description = "Trojan:Win32/UserAccDiscovery.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 20 00 75 00 73 00 65 00 72 00 } //1 net.exe user
	condition:
		((#a_00_0  & 1)*1) >=1
 
}