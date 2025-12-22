
rule Trojan_BAT_PureLogStealer_ASLB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ASLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f ?? 00 00 0a 13 09 16 7e ?? 00 00 04 7b ?? 00 00 04 2d d5 26 16 2b d1 07 28 ?? 00 00 0a 13 04 17 7e ?? 00 00 04 7b ?? 00 00 04 2c bc 26 17 2b b8 } //4
		$a_03_1 = {26 16 2b b0 00 11 08 28 ?? 00 00 0a 0d 18 7e ?? 00 00 04 7b ?? 00 00 04 2c 06 26 16 2b 02 06 4a } //2
		$a_03_2 = {11 0a 11 09 16 73 ?? 00 00 0a 13 05 16 7e ?? 00 00 04 7b ?? 00 00 04 2d 08 26 16 2b 04 06 1a 58 4a } //2
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}