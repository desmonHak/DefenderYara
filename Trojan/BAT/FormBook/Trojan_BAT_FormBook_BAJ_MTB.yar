
rule Trojan_BAT_FormBook_BAJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 12 09 28 ?? 00 00 0a 6e 20 df 03 00 00 6a 5a 12 09 28 ?? 00 00 0a 6e 20 bb 01 00 00 6a 5a 58 12 09 28 ?? 00 00 0a 6e 20 c7 00 00 00 6a 5a 58 13 0d 11 0d 07 6a 61 13 0d 11 0d 19 6a 5f 18 6a 33 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}