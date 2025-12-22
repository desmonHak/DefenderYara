
rule Trojan_BAT_Jalapeno_BAG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 09 02 16 02 8e 69 6f ?? 00 00 0a 38 ?? 00 00 00 38 ?? 00 00 00 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00 45 01 00 00 00 13 00 00 00 fe 0c 00 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 11 01 6f ?? 00 00 0a 73 ?? 00 00 0a 13 03 38 ?? 00 00 00 11 09 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b 51 00 00 04 3a b6 ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 00 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}