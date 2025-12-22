
rule Trojan_Win32_SusPrivChecks_D{
	meta:
		description = "Trojan:Win32/SusPrivChecks.D,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 2e 65 78 65 } //wmic.exe  1
		$a_80_1 = {6c 6f 67 69 63 61 6c 64 69 73 6b } //logicaldisk  1
		$a_80_2 = {66 72 65 65 73 70 61 63 65 } //freespace  1
		$a_80_3 = {63 61 70 74 69 6f 6e } //caption  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}