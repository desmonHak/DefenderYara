
rule Trojan_BAT_NjRat_ABCB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.ABCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 05 9a 28 ?? 00 00 06 13 06 12 04 11 04 8e 69 11 06 8e 69 58 28 ?? 00 00 2b 11 06 16 11 04 11 04 8e 69 11 06 8e 69 59 11 06 8e 69 28 ?? 00 00 06 11 05 17 58 13 05 11 05 06 8e 69 32 c0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}