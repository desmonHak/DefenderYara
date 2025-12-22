
rule Trojan_Win32_Emotet_EVWP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.EVWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c2 8b 4d fc 2b c8 89 4d fc 8b 55 f4 2b 55 dc 89 55 f4 } //2
		$a_01_1 = {03 55 f8 8b 45 e4 03 45 f8 8a 08 88 0a 83 7d f8 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}