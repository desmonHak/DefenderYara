
rule Trojan_BAT_Ghostrat_AGT_MTB{
	meta:
		description = "Trojan:BAT/Ghostrat.AGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 16 13 05 2b 2f 28 ?? 00 00 06 13 06 72 ?? 01 00 70 12 05 28 ?? 00 00 0a 72 ?? 02 00 70 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 11 05 17 58 13 05 11 05 1f 0f } //1
		$a_01_1 = {73 00 73 00 2e 00 74 00 61 00 6e 00 79 00 65 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 } //4 ss.tanye.online
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}