
rule Trojan_BAT_NjRat_SLBA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.SLBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 28 12 00 00 06 0b 06 07 28 13 00 00 06 0c 08 28 30 00 00 0a 28 14 00 00 06 0d 28 31 00 00 0a 72 ?? ?? ?? 70 28 32 00 00 0a 13 04 11 04 09 28 33 00 00 0a 00 11 04 28 34 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}