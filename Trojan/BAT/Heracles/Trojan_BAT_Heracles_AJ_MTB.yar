
rule Trojan_BAT_Heracles_AJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 1f 0a 11 0d 1f 0a 95 11 0e 1f 0a 95 5a 9e 11 18 20 41 ac f4 f4 5a 20 86 70 d1 9b 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}