
rule Trojan_BAT_Amadey_AMY_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 17 d2 13 2f 11 17 1e 63 d1 13 17 11 15 11 09 91 13 2a 11 15 11 09 11 24 11 2a 61 11 1c 19 58 61 11 2f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}