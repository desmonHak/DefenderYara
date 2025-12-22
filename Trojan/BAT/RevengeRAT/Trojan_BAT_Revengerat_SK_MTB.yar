
rule Trojan_BAT_Revengerat_SK_MTB{
	meta:
		description = "Trojan:BAT/Revengerat.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e 0b 00 00 04 06 07 91 6f 2d 00 00 0a 00 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}