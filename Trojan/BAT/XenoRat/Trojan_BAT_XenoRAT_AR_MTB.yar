
rule Trojan_BAT_XenoRAT_AR_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 05 00 fe 09 00 00 28 a8 00 00 06 fe 09 00 00 8e 69 6f 1c 00 00 0a fe 0c 05 00 6f 1d 00 00 0a fe 0c 04 00 6f 1e 00 00 0a fe 0e 00 00 de 20 } //20
		$a_01_1 = {fe 09 01 00 8e 69 fe 09 02 00 59 8d 3a 00 00 01 fe 0e 00 00 fe 09 01 00 fe 09 02 00 fe 0c 00 00 28 c5 00 00 06 fe 0c 00 00 8e 69 28 35 00 00 0a } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}