
rule Trojan_BAT_MythicApollo_AMP_MTB{
	meta:
		description = "Trojan:BAT/MythicApollo.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 43 73 4b 01 00 06 13 05 11 05 06 7d d1 00 00 04 11 05 09 11 04 9a 7d d0 00 00 04 11 05 7b d0 00 00 04 07 11 05 fe 06 4c 01 00 06 73 1e 02 00 0a 6f ?? ?? ?? 0a 2c 02 de 12 de 03 26 de 00 11 04 17 58 13 04 11 04 09 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}