
rule Trojan_Win32_Fareit_BE_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 08 8b c7 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 88 08 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}