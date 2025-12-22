
rule Trojan_BAT_DarkTortilla_PGDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.PGDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 2c 06 72 ?? 76 00 70 0a 1f 64 28 ?? 00 00 0a 00 1f 1a 28 ?? ?? 00 0a 72 ?? 76 00 70 28 ?? ?? 00 0a 0b 73 72 01 00 06 0c 08 28 ?? ?? 00 0a 00 de 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}