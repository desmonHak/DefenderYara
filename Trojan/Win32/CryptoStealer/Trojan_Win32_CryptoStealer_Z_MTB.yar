
rule Trojan_Win32_CryptoStealer_Z_MTB{
	meta:
		description = "Trojan:Win32/CryptoStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 28 5f 30 78 } //1 function(_0x
		$a_01_1 = {70 61 72 73 65 69 6e 74 28 5f 30 78 } //1 parseint(_0x
		$a_01_2 = {77 61 6c 6c 65 74 } //1 wallet
		$a_01_3 = {62 69 74 63 6f 69 6e } //1 bitcoin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}