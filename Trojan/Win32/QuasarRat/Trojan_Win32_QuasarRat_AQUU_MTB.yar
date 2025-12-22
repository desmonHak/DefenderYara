
rule Trojan_Win32_QuasarRat_AQUU_MTB{
	meta:
		description = "Trojan:Win32/QuasarRat.AQUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 0f b6 04 02 44 31 c7 41 88 3c 19 48 ff c3 4c 89 c8 4c 89 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}