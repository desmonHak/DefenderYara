
rule Trojan_Win32_PsLoadz_A_MTB{
	meta:
		description = "Trojan:Win32/PsLoadz.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {24 00 5f 00 20 00 2d 00 62 00 78 00 6f 00 72 00 } //1 $_ -bxor
		$a_00_1 = {2d 00 6a 00 6f 00 69 00 6e 00 } //1 -join
		$a_00_2 = {2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5d 00 3a 00 3a 00 24 00 } //1 .Assembly]::$
		$a_00_3 = {5d 00 3a 00 3a 00 44 00 65 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 } //1 ]::Decompress
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}