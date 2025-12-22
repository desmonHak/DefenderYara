
rule Trojan_BAT_Darkcloud_ZSK_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.ZSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 13 0a 03 06 6f ?? 00 00 0a 59 13 0b 11 0b 16 fe 02 16 fe 01 13 0f 11 0f 2c 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}