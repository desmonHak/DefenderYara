
rule Trojan_BAT_AuraStealer_AUKB_MTB{
	meta:
		description = "Trojan:BAT/AuraStealer.AUKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 14 fe 03 13 07 11 07 2c 2a 11 04 08 6f ?? ?? 00 0a 00 11 04 08 6f ?? ?? 00 0a 00 11 04 6f ?? ?? 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? 00 0a 0a de 53 00 de 4b } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}