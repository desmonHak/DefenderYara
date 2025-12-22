
rule Trojan_BAT_DarkTortilla_ZFF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1b 5d 16 fe 01 13 07 11 07 2c 0f 07 11 06 07 11 06 91 20 a9 00 00 00 61 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}