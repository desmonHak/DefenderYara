
rule Trojan_BAT_PureLogs_SH_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 72 01 00 00 70 6f 11 00 00 0a 0a 00 de 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}