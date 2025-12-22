
rule Trojan_BAT_Stealer_AWEB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AWEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 61 04 61 8c ?? 00 00 01 2a } //4
		$a_03_1 = {01 13 06 11 06 16 09 8c ?? 00 00 01 a2 11 06 14 28 ?? 00 00 0a 28 ?? 00 00 0a 02 17 8d ?? 00 00 01 13 07 11 07 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}