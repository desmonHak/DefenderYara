
rule Trojan_Win32_AmsiBypazz_Z_MTB{
	meta:
		description = "Trojan:Win32/AmsiBypazz.Z!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 24 00 } //1 .invoke($
		$a_00_1 = {62 00 79 00 74 00 65 00 5b 00 5d 00 5d 00 24 00 } //1 byte[]]$
		$a_00_2 = {67 00 65 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 28 00 } //1 getmethod(
		$a_00_3 = {3a 00 3a 00 6c 00 6f 00 61 00 64 00 28 00 24 00 } //1 ::load($
		$a_00_4 = {2e 00 73 00 70 00 6c 00 69 00 74 00 } //1 .split
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}