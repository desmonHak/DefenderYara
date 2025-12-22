
rule Trojan_Win32_WMIPersistance_B{
	meta:
		description = "Trojan:Win32/WMIPersistance.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 6f 00 66 00 63 00 6f 00 6d 00 70 00 2e 00 65 00 78 00 65 00 } //1 mofcomp.exe
		$a_00_1 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 61 00 69 00 2d 00 } //1 \temp\ai-
		$a_00_2 = {2e 00 6d 00 6f 00 66 00 } //1 .mof
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}