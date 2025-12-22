
rule Trojan_BAT_NjRat_ACCB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.ACCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 06 9a 28 ?? 00 00 06 13 07 11 05 11 07 6f ?? 00 00 0a 11 06 17 58 13 06 11 06 06 8e 69 32 de 11 05 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 08 11 08 08 28 ?? 00 00 06 11 08 09 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 09 11 09 11 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}