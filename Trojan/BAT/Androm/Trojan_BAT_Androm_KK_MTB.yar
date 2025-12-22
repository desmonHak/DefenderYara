
rule Trojan_BAT_Androm_KK_MTB{
	meta:
		description = "Trojan:BAT/Androm.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 28 67 00 00 06 7e 04 00 00 04 7e 05 00 00 04 72 01 00 00 70 72 ?? 00 00 70 6f 4d 00 00 06 38 00 00 00 00 dd ?? ff ff ff 26 38 00 00 00 00 dd ?? ff ff ff 38 ?? ff ff ff } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}