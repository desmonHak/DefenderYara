
rule Trojan_Win32_ProcessSearchOrderHijack_A{
	meta:
		description = "Trojan:Win32/ProcessSearchOrderHijack.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 6f 00 61 00 6d 00 69 00 } //1 whoami
		$a_00_1 = {68 00 65 00 6c 00 70 00 } //1 help
		$a_00_2 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //1 ipconfig
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}