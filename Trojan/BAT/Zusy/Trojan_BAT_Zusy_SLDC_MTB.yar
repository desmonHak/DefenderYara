
rule Trojan_BAT_Zusy_SLDC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SLDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 0b 06 73 04 00 00 0a 6f 05 00 00 0a 06 72 8e 00 00 70 07 6f 06 00 00 0a 06 73 04 00 00 0a 6f 05 00 00 0a 73 07 00 00 0a 0c 08 07 6f 08 00 00 0a 08 17 6f 09 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}