
rule Trojan_BAT_FormBook_AKK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 15 11 15 2c 05 38 ff 00 00 00 02 11 05 11 06 6f ?? 00 00 0a 13 0a 03 07 6f ?? 00 00 0a 59 13 0b 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}