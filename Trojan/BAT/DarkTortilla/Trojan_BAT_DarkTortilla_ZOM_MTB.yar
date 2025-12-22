
rule Trojan_BAT_DarkTortilla_ZOM_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 1f 09 5d 16 fe 01 13 0a 11 0a 2c 11 11 04 11 09 11 04 11 09 91 20 f3 00 00 00 61 9c 00 00 11 09 17 d6 13 09 11 09 11 08 31 d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}