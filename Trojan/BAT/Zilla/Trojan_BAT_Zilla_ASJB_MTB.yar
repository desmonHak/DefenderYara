
rule Trojan_BAT_Zilla_ASJB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ASJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 6f ?? 00 00 0a 13 04 11 04 2c 3d 00 08 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 01 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0a 00 00 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 72 ?? 00 00 70 6f ?? 00 00 0a 26 15 28 ?? 00 00 0a 00 00 de 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}