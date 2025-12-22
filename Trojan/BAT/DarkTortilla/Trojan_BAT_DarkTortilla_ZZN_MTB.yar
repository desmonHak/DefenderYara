
rule Trojan_BAT_DarkTortilla_ZZN_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 08 02 03 08 91 08 04 28 ?? 01 00 06 9c 08 17 d6 0c 08 07 31 ea 03 0a 2b 00 06 2a } //6
		$a_03_1 = {1f 09 0b 05 04 07 5d 9a 28 ?? 00 00 0a 0c 03 0d 08 09 60 08 66 09 66 60 5f b4 0a 2b 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}