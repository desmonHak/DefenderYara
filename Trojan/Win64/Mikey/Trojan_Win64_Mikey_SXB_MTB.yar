
rule Trojan_Win64_Mikey_SXB_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 c7 83 90 00 00 00 00 00 00 00 48 c7 83 98 00 00 00 08 00 00 00 48 c7 83 a0 00 00 00 00 00 00 00 c6 83 03 01 00 00 01 c6 83 01 01 00 00 00 } //2
		$a_01_1 = {73 72 63 5c 6d 6f 64 75 6c 65 73 5c 62 72 6f 77 73 65 72 5c 69 6e 6a 65 63 74 69 6f 6e 5c 69 6e 6a 65 63 74 6f 72 2e 72 73 } //1 src\modules\browser\injection\injector.rs
		$a_01_2 = {73 72 63 5c 6d 6f 64 75 6c 65 73 5c 62 72 6f 77 73 65 72 5c 63 72 79 70 74 6f 5c 64 65 63 72 79 70 74 2e 72 73 } //1 src\modules\browser\crypto\decrypt.rs
		$a_01_3 = {2d 2d 77 61 6c 6c 65 74 2d 64 6f 77 6e 6c 6f 61 64 } //1 --wallet-download
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}