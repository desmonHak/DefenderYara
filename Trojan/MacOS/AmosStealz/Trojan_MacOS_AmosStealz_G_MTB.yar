
rule Trojan_MacOS_AmosStealz_G_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealz.G!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 00 65 00 74 00 70 00 77 00 64 00 28 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1 getpwd(username
		$a_00_1 = {63 00 68 00 65 00 63 00 6b 00 76 00 61 00 6c 00 69 00 64 00 28 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1 checkvalid(username
		$a_00_2 = {64 00 69 00 73 00 70 00 6c 00 61 00 79 00 20 00 64 00 69 00 61 00 6c 00 6f 00 67 00 } //1 display dialog
		$a_00_3 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}