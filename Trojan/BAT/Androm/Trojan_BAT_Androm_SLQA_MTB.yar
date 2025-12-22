
rule Trojan_BAT_Androm_SLQA_MTB{
	meta:
		description = "Trojan:BAT/Androm.SLQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 12 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 08 00 00 06 28 02 00 00 0a 6f 03 00 00 0a 13 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}