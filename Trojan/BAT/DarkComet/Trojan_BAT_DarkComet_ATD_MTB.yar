
rule Trojan_BAT_DarkComet_ATD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0a 06 09 16 09 8e b7 6f ?? 00 00 0a 13 04 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}