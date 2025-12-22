
rule Trojan_Win32_Androm_EFVY_MTB{
	meta:
		description = "Trojan:Win32/Androm.EFVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc } //2
		$a_01_1 = {03 4d f8 8b 55 e0 03 55 f8 8a 02 88 01 83 7d f8 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}