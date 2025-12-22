
rule Trojan_BAT_DarkCloud_APDB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.APDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {38 cf 00 00 00 2d 0b 72 ?? ?? 00 70 38 ?? 00 00 00 7a 38 ?? 00 00 00 38 ?? 00 00 00 06 03 7b ?? 00 00 04 03 7b ?? 00 00 04 6f ?? 00 00 0a 0b 1c 2c 0a 17 2c 07 2b 62 38 ?? 00 00 00 38 ?? 00 00 00 38 ?? 00 00 00 17 38 ?? 00 00 00 0d 02 09 6f ?? 00 00 0a 1d 2c 06 09 6f ?? 00 00 0a de 0a } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}