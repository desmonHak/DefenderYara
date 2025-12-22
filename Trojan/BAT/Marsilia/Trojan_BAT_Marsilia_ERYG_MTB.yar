
rule Trojan_BAT_Marsilia_ERYG_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.ERYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 07 16 07 8e 69 ?? ?? ?? ?? ?? 0c 07 16 03 11 04 08 ?? ?? ?? ?? ?? 11 0b 07 16 08 ?? ?? ?? ?? ?? 09 08 58 0d 11 04 08 58 13 04 11 11 17 58 13 11 11 11 6a 11 0d 32 c7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}