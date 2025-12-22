
rule Trojan_BAT_PureLogs_EAOB_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.EAOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0c 2b 1e 11 0c ?? ?? ?? ?? ?? 13 24 11 0a 11 24 11 14 59 61 13 0a 11 14 19 11 0a 58 1e 63 59 13 14 11 0c ?? ?? ?? ?? ?? 2d d9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}