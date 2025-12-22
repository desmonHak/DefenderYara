
rule Trojan_Win32_SuspNetworkConfig_A{
	meta:
		description = "Trojan:Win32/SuspNetworkConfig.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 75 72 6c 2e 65 78 65 20 } //curl.exe   1
		$a_00_1 = {2e 00 63 00 6f 00 6d 00 } //1 .com
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}