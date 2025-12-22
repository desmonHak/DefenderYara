
rule Trojan_BAT_QuasarRat_SLTU_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.SLTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 07 2d 07 11 07 1a 58 4b 2b 08 11 07 19 d3 1a 5a 58 4b } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_81_3 = {73 65 72 76 65 72 31 2e 65 78 65 } //2 server1.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*2) >=8
 
}