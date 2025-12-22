
rule Trojan_MacOS_AmosStealz_D_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealz.D!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {29 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 28 00 77 00 72 00 69 00 74 00 65 00 6d 00 69 00 6e 00 64 00 } //1 )telegram(writemind
		$a_00_1 = {29 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 46 00 6c 00 61 00 67 00 28 00 } //1 )encryptFlag(
		$a_00_2 = {29 00 64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 )do shell script
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}