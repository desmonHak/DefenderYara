
rule Trojan_BAT_Quasar_ZVL_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ZVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 05 09 6f ?? 01 00 0a 13 06 12 06 28 ?? 01 00 0a 12 06 28 ?? 01 00 0a 58 86 12 06 28 ?? 01 00 0a 58 86 19 5b b4 13 07 11 07 6b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}