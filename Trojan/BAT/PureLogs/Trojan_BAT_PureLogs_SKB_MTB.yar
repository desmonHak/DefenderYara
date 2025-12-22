
rule Trojan_BAT_PureLogs_SKB_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SKB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 0b 00 00 0a 0a 38 1b 00 00 00 00 00 02 28 0a 00 00 06 7d 04 00 00 04 dd 26 00 00 00 26 00 00 dd 00 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}