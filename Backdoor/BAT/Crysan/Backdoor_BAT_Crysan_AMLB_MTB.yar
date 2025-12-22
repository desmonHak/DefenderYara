
rule Backdoor_BAT_Crysan_AMLB_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AMLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b de 0a 08 2c 06 08 6f ?? 00 00 0a dc 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0d 09 14 28 ?? 00 00 0a 2d 63 09 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}