
rule Trojan_Win32_AmsiBypazz_GGB_MTB{
	meta:
		description = "Trojan:Win32/AmsiBypazz.GGB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 5b 00 69 00 6e 00 74 00 5d 00 24 00 } //1 [char]([int]$
		$a_00_1 = {2d 00 62 00 78 00 6f 00 72 00 20 00 24 00 } //1 -bxor $
		$a_00_2 = {2d 00 6a 00 6f 00 69 00 6e 00 } //1 -join
		$a_00_3 = {2e 00 53 00 70 00 6c 00 69 00 74 00 28 00 } //1 .Split(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}