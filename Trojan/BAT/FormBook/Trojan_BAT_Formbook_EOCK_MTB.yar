
rule Trojan_BAT_Formbook_EOCK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EOCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 05 09 5b 13 0d 11 05 11 0d 09 5a 59 13 0e 06 11 0d 11 0e 58 0e 04 58 20 ff 00 00 00 5f 91 13 0f 02 11 0d 11 0e ?? ?? ?? ?? ?? 13 10 04 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}