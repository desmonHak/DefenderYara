
rule Trojan_BAT_FormBook_MCJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0f 1f 90 01 01 5a 11 0a 1b 63 61 61 13 0a 16 13 10 } //1
		$a_01_1 = {4d 00 61 00 74 00 68 00 00 07 53 00 54 00 44 00 00 31 44 00 65 00 70 00 65 00 6e 00 64 00 65 00 6e 00 63 00 79 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}