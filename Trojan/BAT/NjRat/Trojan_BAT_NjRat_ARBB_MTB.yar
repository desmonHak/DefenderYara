
rule Trojan_BAT_NjRat_ARBB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.ARBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 03 09 03 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a 28 ?? 00 00 0a da 13 04 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 09 17 d6 0d 00 09 08 fe 02 16 fe 01 13 05 11 05 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}