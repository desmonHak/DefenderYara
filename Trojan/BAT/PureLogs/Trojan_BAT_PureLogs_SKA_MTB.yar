
rule Trojan_BAT_PureLogs_SKA_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SKA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b ea 02 7b 1e 00 00 04 18 5a 8d 1a 00 00 01 0a 17 0c 2b d8 02 7b 1d 00 00 04 16 06 16 02 7b 1e 00 00 04 28 86 00 00 0a 18 0c 2b c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}