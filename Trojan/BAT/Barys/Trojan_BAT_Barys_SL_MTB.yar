
rule Trojan_BAT_Barys_SL_MTB{
	meta:
		description = "Trojan:BAT/Barys.SL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 00 28 75 00 00 06 7e 04 00 00 04 7e 05 00 00 04 72 01 00 00 70 72 51 00 00 70 14 6f 53 00 00 06 38 00 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}