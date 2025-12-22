
rule Trojan_BAT_DarkCloud_ABJB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ABJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 1c 12 1c 28 ?? 00 00 0a 13 17 03 06 6f ?? 00 00 0a 59 13 18 18 13 1d 2b 26 00 06 11 17 11 1d 1e 5a 1f 1f 5f 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 00 11 1d 17 59 13 1d 11 18 17 59 13 18 11 1d 16 32 07 11 18 16 fe 02 2b 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}