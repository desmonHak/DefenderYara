
rule Trojan_BAT_Heracles_SLDQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 01 00 00 04 02 1e 58 11 06 16 11 04 1a 59 28 2d 00 00 0a 11 06 a5 01 00 00 1b 0b 11 08 20 1a 69 35 87 5a 20 d0 8b c4 8e 61 38 c4 fd ff ff } //2
		$a_01_1 = {44 65 63 72 79 70 74 69 6f 6e 4b 65 79 } //2 DecryptionKey
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}