
rule Trojan_BAT_SnakeLogger_ELAK_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ELAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 02 8e 69 17 da 17 d6 ?? ?? ?? ?? ?? 13 09 11 08 11 09 16 11 09 8e 69 ?? ?? ?? ?? ?? 13 0a 11 0a 17 da 17 d6 ?? ?? ?? ?? ?? 13 0b 11 09 11 0b 11 0a ?? ?? ?? ?? ?? 00 11 0b 0a de 51 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}