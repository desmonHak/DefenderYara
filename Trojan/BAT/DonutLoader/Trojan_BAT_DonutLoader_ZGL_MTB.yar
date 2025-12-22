
rule Trojan_BAT_DonutLoader_ZGL_MTB{
	meta:
		description = "Trojan:BAT/DonutLoader.ZGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 3a 74 ff ff ff 06 13 04 2b 00 11 04 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}