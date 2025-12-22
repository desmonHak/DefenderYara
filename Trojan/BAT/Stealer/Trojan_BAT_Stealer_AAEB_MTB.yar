
rule Trojan_BAT_Stealer_AAEB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AAEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {09 11 0b 20 83 00 00 00 5a 61 13 0c 16 13 0d } //4
		$a_01_1 = {11 0c 16 5f 13 11 11 11 19 5d 13 12 17 11 11 58 19 5d 13 13 } //3
		$a_01_2 = {08 94 11 08 61 0e 05 1f 0f 5f 58 9e } //2
		$a_01_3 = {8e 69 5d 94 61 58 13 0c } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=11
 
}