
rule Trojan_BAT_RedLineStealer_BAA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 5b 17 da 17 d6 8d 23 00 00 01 0a 16 02 ?? ?? 00 00 0a 17 da 0d 0c 2b 18 06 08 18 5b 02 08 18 ?? ?? 00 00 0a 1f 10 ?? ?? 00 00 0a 9c 08 18 d6 0c 08 09 31 e4 06 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}