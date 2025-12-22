
rule Trojan_BAT_Heracles_BAE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 91 58 20 ff 00 00 00 5f 91 06 11 07 91 61 d2 9c 11 07 17 58 13 07 11 07 06 8e 69 17 59 31 a7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}