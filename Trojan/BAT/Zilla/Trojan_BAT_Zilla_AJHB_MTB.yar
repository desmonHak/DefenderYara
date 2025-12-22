
rule Trojan_BAT_Zilla_AJHB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AJHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 73 04 00 00 06 7d 01 00 00 04 02 73 06 00 00 06 7d 02 00 00 04 02 7b 01 00 00 04 6f ?? 00 00 06 0a 06 39 16 00 00 00 06 16 06 8e 69 28 ?? 00 00 0a 02 7b 02 00 00 04 06 6f ?? 00 00 06 2a } //5
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}