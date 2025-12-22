
rule Trojan_BAT_CryptInject_MCHI_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MCHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 07 16 13 08 2b 12 11 05 11 07 11 08 91 6f 0d 00 00 0a 11 08 17 58 13 08 } //1
		$a_01_1 = {6c 00 79 00 00 15 47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 00 09 4c 00 6f 00 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}