
rule Trojan_BAT_Remcos_ZAL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 16 02 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 06 fe ?? 46 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 2a } //6
		$a_03_1 = {25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 2b 24 19 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}