
rule Trojan_BAT_DarkTortilla_ZCL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 06 11 05 06 11 05 91 20 d3 00 00 00 61 9c 00 00 11 05 17 d6 13 05 11 05 11 04 31 d7 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}