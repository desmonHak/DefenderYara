
rule Trojan_BAT_DarkTortillla_GKV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortillla.GKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 8e 69 17 da 0d 16 13 04 2b 15 07 11 04 07 11 04 91 20 bb 00 00 00 61 b4 9c 11 04 1b d6 13 04 11 04 09 31 e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}