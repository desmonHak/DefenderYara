
rule Trojan_BAT_PureLogs_SJ_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 10 00 00 06 0a de 03 26 de 00 06 2c 03 16 2b 03 17 2b 00 2d e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}