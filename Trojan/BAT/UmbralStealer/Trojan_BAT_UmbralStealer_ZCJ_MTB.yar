
rule Trojan_BAT_UmbralStealer_ZCJ_MTB{
	meta:
		description = "Trojan:BAT/UmbralStealer.ZCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d ?? 00 00 01 0b 16 0c 2b 0f 00 07 08 06 08 91 03 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}