
rule Trojan_BAT_DarkTortilla_EEV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.EEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 1a 5d 16 fe 01 13 09 11 09 2c 0f 02 11 08 02 11 08 91 20 c4 00 00 00 61 b4 9c 11 08 17 d6 13 08 11 08 11 07 31 d8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}