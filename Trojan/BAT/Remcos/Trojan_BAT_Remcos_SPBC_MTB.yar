
rule Trojan_BAT_Remcos_SPBC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? ?? ?? 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c 2b 0c 00 28 ?? 00 00 06 0c de 03 26 de 00 08 2c f1 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 02 09 28 ?? 00 00 06 de 0a 06 2c 06 06 6f ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}