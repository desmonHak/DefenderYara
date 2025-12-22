
rule Trojan_Win32_Kkrunchy_GVB_MTB{
	meta:
		description = "Trojan:Win32/Kkrunchy.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 06 0f b6 50 01 0f b6 00 8a 4d 1c fe c6 8b 04 85 05 3b a7 00 d3 ea 19 c9 31 c8 29 c8 3b 55 14 74 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}