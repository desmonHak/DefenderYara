
rule Trojan_BAT_Zilla_MK_MTB{
	meta:
		description = "Trojan:BAT/Zilla.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 20 00 00 00 00 38 60 ff ff ff 72 c5 00 00 70 73 15 00 00 0a 7a 03 28 16 00 00 0a 3a b5 ff ff ff 38 79 ff ff ff 72 d7 00 00 70 73 15 00 00 0a 7a 02 28 17 00 00 0a } //15
		$a_01_1 = {17 73 07 00 00 0a 13 04 38 20 00 00 00 fe 0c 05 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 11 01 6f 08 00 00 0a 13 06 38 91 00 00 00 00 11 04 02 16 02 8e 69 6f 09 00 00 0a 38 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}