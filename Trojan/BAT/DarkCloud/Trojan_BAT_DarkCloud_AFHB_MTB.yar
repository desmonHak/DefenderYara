
rule Trojan_BAT_DarkCloud_AFHB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AFHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 0c 11 0c 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 11 0c 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 11 0c 17 6f ?? ?? 00 0a 00 11 0c 18 6f ?? ?? 00 0a 00 00 11 0c 6f ?? ?? 00 0a 13 0d 11 0d 11 05 16 11 05 8e 69 6f ?? ?? 00 0a 13 06 de 0e } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}