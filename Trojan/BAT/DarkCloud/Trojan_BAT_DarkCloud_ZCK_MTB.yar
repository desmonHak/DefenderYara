
rule Trojan_BAT_DarkCloud_ZCK_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ZCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 fe 06 67 00 00 06 73 ?? 00 00 0a 7d ?? 00 00 04 06 73 ?? 00 00 0a 25 16 06 fe 06 68 00 00 06 73 ?? 00 00 0a 6f ?? 00 00 0a 00 25 17 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}