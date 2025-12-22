
rule Trojan_BAT_VIPKeyLogger_ZBM_MTB{
	meta:
		description = "Trojan:BAT/VIPKeyLogger.ZBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 0e 06 69 11 2e 1f 0d 5a 58 11 2f 1d 5a 58 61 13 30 00 02 11 2e 11 2f 6f ?? 00 00 0a 13 31 04 03 6f ?? 00 00 0a 59 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}