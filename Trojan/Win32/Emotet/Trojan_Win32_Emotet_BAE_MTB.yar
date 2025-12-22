
rule Trojan_Win32_Emotet_BAE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 05 03 4d e8 33 c1 8b 4d f8 2b c8 89 4d f8 8b 45 f8 c1 e0 04 03 45 e4 8b 4d f8 03 4d f4 33 c1 8b 4d f8 c1 e9 05 03 4d e0 33 c1 8b 4d fc 2b c8 89 4d fc 8b 45 f4 2b 45 dc 89 45 f4 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}