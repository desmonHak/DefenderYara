
rule Trojan_BAT_DarkTortilla_ASCB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ASCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 13 05 11 05 6f ?? ?? 00 0a 13 06 73 ?? ?? 00 0a 13 07 11 07 11 06 17 73 ?? ?? 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? 00 0a 00 11 08 6f ?? ?? 00 0a 00 11 07 6f ?? ?? 00 0a 0a de 45 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}