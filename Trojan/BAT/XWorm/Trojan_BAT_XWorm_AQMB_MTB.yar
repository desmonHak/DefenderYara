
rule Trojan_BAT_XWorm_AQMB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AQMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0c 09 16 8c ?? 00 00 01 08 6f ?? 00 00 0a 17 da 8c ?? 00 00 01 17 8c ?? 00 00 01 12 07 12 03 28 ?? 00 00 0a 2c 28 06 08 09 28 ?? 00 00 0a 16 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 09 11 07 12 03 28 ?? 00 00 0a 2d d8 de 0f 25 28 ?? 00 00 0a 13 04 28 ?? 00 00 0a de 00 06 6f ?? 00 00 0a 0b 2b 00 07 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}