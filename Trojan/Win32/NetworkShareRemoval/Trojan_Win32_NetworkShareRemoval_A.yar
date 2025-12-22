
rule Trojan_Win32_NetworkShareRemoval_A{
	meta:
		description = "Trojan:Win32/NetworkShareRemoval.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6e 00 65 00 74 00 [0-08] 20 00 75 00 73 00 65 00 20 00 } //1
		$a_00_1 = {20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //1  /delete
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}