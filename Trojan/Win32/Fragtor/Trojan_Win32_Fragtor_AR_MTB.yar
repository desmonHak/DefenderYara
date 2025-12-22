
rule Trojan_Win32_Fragtor_AR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 46 04 03 c1 8b 4d b4 03 d0 41 8b 45 b4 83 e0 03 89 4d b4 8a 44 05 d0 30 02 33 c0 8b 55 b8 3b cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}