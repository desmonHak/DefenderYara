
rule Trojan_BAT_DarkCloud_AOKB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AOKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 1e 5d 2c 03 03 2b 07 03 20 a4 00 00 00 61 b4 0a 2b 00 06 2a } //5
		$a_03_1 = {2b a2 14 14 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 1f 18 8c ?? 00 00 01 a2 14 14 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}