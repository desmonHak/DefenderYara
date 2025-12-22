
rule Trojan_BAT_Heracles_SM_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 6f 2a 00 00 06 04 6f 2c 00 00 06 17 16 6f 10 00 00 0a 04 6f 2e 00 00 06 1f 38 6f 11 00 00 0a 25 14 } //10
		$a_01_1 = {02 20 00 00 00 01 7d 21 00 00 04 38 00 00 00 00 02 1a 7d 22 00 00 04 38 00 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}