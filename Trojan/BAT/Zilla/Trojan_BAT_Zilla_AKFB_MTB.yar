
rule Trojan_BAT_Zilla_AKFB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AKFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 09 11 09 72 ?? ?? 00 70 08 28 ?? 00 00 06 11 09 72 ?? ?? 00 70 09 28 ?? 00 00 06 11 09 72 ?? ?? 00 70 17 16 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 01 13 0a 11 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 04 11 04 } //5
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}