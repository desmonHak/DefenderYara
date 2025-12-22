
rule Trojan_BAT_DarkCloud_AZDB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AZDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 02 7b ?? 00 00 04 0c 16 0d 08 12 03 28 ?? 00 00 0a 00 00 73 ?? 00 00 0a 13 04 11 04 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 05 07 11 05 17 73 ?? 00 00 0a 13 06 00 03 11 06 6f ?? 00 00 0a 00 11 06 6f ?? 00 00 0a 00 07 16 6a 6f ?? 00 00 0a 00 00 dd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}