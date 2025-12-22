
rule Trojan_BAT_DCRat_MZV_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 38 bc 00 00 00 00 28 b4 08 00 0a 13 09 11 09 28 ?? 08 00 0a 72 27 07 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 28 ?? 08 00 0a 72 69 07 00 70 6f ?? 00 00 0a 6f ?? 08 00 0a 00 11 09 11 09 6f ?? 08 00 0a 11 09 6f ?? 08 00 0a 6f ?? 08 00 0a 13 0a 02 03 9a 28 ?? 00 00 0a 13 0b 11 0b 73 aa 08 00 0a 13 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}