
rule Trojan_BAT_NjRat_SLAA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.SLAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 28 14 00 00 0a 74 12 00 00 01 0b 07 72 ?? 00 00 70 6f 15 00 00 0a 00 07 6f 16 00 00 0a 0c 08 6f 17 00 00 0a 28 18 00 00 0a 73 19 00 00 0a 0d 09 6f 1a 00 00 0a 13 04 11 04 28 1b 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}