
rule Trojan_BAT_PureLogs_SG_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 45 03 00 00 00 04 00 00 00 0c 00 00 00 19 00 00 00 16 0d 2b ea 08 16 31 13 17 0d 2b e2 03 06 16 08 6f 91 00 00 0a 18 0d 2b d5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}