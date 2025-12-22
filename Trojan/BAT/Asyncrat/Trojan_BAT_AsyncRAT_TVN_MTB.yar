
rule Trojan_BAT_AsyncRAT_TVN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.TVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 07 6f ?? 00 00 0a 13 0a 03 07 6f ?? 00 00 0a 59 13 0b 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 13 13 11 13 2c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}