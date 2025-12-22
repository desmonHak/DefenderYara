
rule Trojan_Win32_SuspWmiPs_E{
	meta:
		description = "Trojan:Win32/SuspWmiPs.E,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 20 71 66 65 20 67 65 74 } //wmic qfe get  1
		$a_80_1 = {64 65 73 63 72 69 70 74 69 6f 6e } //description  1
		$a_80_2 = {69 6e 73 74 61 6c 6c 65 64 4f 6e } //installedOn  1
		$a_80_3 = {2f 66 6f 72 6d 61 74 3a 63 73 76 } ///format:csv  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}