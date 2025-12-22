
rule Trojan_Win32_Copak_BAB_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc 8b 55 f4 2b 55 dc 89 55 f4 eb ?? b8 04 00 00 00 6b c8 00 8b 55 08 8b 45 fc 89 04 0a b9 04 00 00 00 c1 e1 00 8b 55 08 8b 45 f8 89 04 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}