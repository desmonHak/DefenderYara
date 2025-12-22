
rule Trojan_BAT_FormBook_SO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5a 11 0e 1a 63 61 61 13 0e } //1
		$a_81_1 = {53 6f 6c 61 72 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 SolarSystem.Properties.Resources
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}