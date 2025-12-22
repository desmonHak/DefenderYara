
rule Trojan_BAT_Heracles_RT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 91 1b 62 06 07 91 19 63 60 d2 9c 06 07 06 07 91 03 07 03 8e 69 5d 91 61 04 07 04 8e 69 5d 91 61 05 07 05 8e 69 5d 91 61 d2 9c 07 17 58 0b } //4
		$a_01_1 = {06 07 03 02 07 91 91 9c 07 17 58 0b 07 02 8e 69 32 ee } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}