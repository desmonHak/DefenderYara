
rule Trojan_BAT_DarkTortilla_ZXM_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 0a 16 0b 2b 11 02 07 02 07 91 07 03 28 ?? 02 00 06 9c 07 17 d6 0b 07 06 31 eb } //6
		$a_03_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 02 00 0a 02 28 ?? 02 00 06 28 ?? 02 00 0a 0a 2b 00 06 2a } //4
		$a_03_2 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4+(#a_03_2  & 1)*2) >=12
 
}