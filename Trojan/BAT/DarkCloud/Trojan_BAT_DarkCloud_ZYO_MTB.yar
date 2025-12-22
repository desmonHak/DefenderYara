
rule Trojan_BAT_DarkCloud_ZYO_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ZYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 13 1f 3b 5a 61 08 11 ?? 11 ?? 58 1f 18 5d 94 58 13 14 00 02 11 ?? 11 ?? 6f ?? 00 00 0a 13 15 04 03 6f ?? 00 00 0a 59 13 16 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}