
rule Trojan_BAT_Heracles_BAF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 11 00 00 0a 13 09 38 00 00 00 00 00 11 09 11 0b 16 73 16 00 00 0a 13 0a 38 00 00 00 00 00 73 08 00 00 0a 13 06 38 00 00 00 00 00 11 0a 11 06 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 07 38 00 00 00 00 dd 24 01 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}