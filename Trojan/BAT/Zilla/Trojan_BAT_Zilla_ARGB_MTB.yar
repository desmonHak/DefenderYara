
rule Trojan_BAT_Zilla_ARGB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ARGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 12 11 2c 11 12 11 2c 91 11 14 11 2c 11 13 5d 91 61 9c 11 06 17 d6 13 06 11 06 17 d6 13 06 11 06 17 d6 13 06 11 06 17 d6 13 06 11 06 17 d6 13 06 11 2c 17 d6 13 2c } //5
		$a_01_1 = {11 12 11 2c 11 12 11 2c 91 11 15 11 2c 11 13 5d 91 61 9c 11 06 17 d6 13 06 11 06 17 d6 13 06 11 06 17 d6 13 06 11 06 17 d6 13 06 11 06 17 d6 13 06 11 2c 17 d6 13 2c } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}