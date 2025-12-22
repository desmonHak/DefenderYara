
rule Trojan_BAT_Remcos_ZIN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 11 18 58 19 5d 13 1b 19 8d ?? 00 00 01 13 1c 11 1c 16 12 15 28 ?? 00 00 0a 9c 11 1c 17 12 15 28 ?? 00 00 0a 9c 11 1c 18 12 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}