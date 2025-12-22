
rule Trojan_BAT_Remcos_ZFM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 6d 5a 11 0a 1b 63 61 61 13 0a 16 13 10 38 ?? 00 00 00 02 11 0f 11 10 6f ?? 00 00 0a 13 11 04 03 6f ?? 00 00 0a 59 13 12 11 12 19 31 03 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}