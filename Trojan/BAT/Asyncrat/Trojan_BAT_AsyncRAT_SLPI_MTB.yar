
rule Trojan_BAT_AsyncRAT_SLPI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SLPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 0a 20 55 f6 01 00 28 ?? 00 00 06 25 26 0b 02 06 28 31 00 00 0a 25 26 07 28 6f 00 00 06 25 26 0c 28 ?? 00 00 0a 25 26 08 6f ?? 00 00 0a 25 26 14 20 58 f6 01 00 28 ?? 00 00 06 25 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}