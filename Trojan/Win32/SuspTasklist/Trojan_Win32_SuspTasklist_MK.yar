
rule Trojan_Win32_SuspTasklist_MK{
	meta:
		description = "Trojan:Win32/SuspTasklist.MK,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {74 61 73 6b 6c 69 73 74 } //tasklist  1
		$a_00_1 = {2d 00 76 00 } //1 -v
		$a_00_2 = {2f 00 76 00 } //1 /v
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}