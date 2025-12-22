
rule Trojan_BAT_PureLogs_AD_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 14 00 fe 0e 15 00 20 ce 8a f8 01 20 51 f5 b2 79 61 20 02 df cf 6c 61 fe 0e 14 00 fe 0c 12 00 20 0f 0f 0f 0f 5f fe 0e 17 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}