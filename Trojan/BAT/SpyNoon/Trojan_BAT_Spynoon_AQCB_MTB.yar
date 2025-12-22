
rule Trojan_BAT_Spynoon_AQCB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AQCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 2d 0b 72 ?? ?? 00 70 73 ?? 00 00 0a 7a 73 ?? 00 00 0a 0a 06 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 03 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a de 0a } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}