
rule Trojan_BAT_Remcos_ZRM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 11 0b 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 20 de 00 00 00 6a 61 b4 6f ?? 00 00 0a 00 11 0b 15 d6 13 0b 11 0b 16 2f d7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}