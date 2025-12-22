
rule Trojan_BAT_FormBook_AKI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 2d 03 17 2b 01 15 0b 04 6c 0e 05 5a 69 0e 06 58 0c 03 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 07 5a 07 5a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}