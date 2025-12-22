
rule Trojan_BAT_Amadey_SPYT_MTB{
	meta:
		description = "Trojan:BAT/Amadey.SPYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 17 11 15 11 09 91 13 2a 11 15 11 09 11 24 11 2a 61 11 1c 19 58 61 11 2f 61 d2 9c } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}