
rule Trojan_BAT_Remcos_AB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {3a 5a 01 00 00 11 07 02 6f ?? 00 00 0a 3c 4d 01 00 00 11 08 02 6f ?? 00 00 0a 3c 11 01 00 00 06 6f ?? 00 00 0a 03 3c 34 01 00 00 02 11 07 11 08 6f ?? 00 00 0a 13 09 03 06 6f ?? 00 00 0a 59 13 0a 11 0a 11 04 61 16 2f 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}