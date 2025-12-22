
rule Trojan_BAT_FormBook_GXV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 16 1f 3b 5a 61 0e 04 18 62 61 13 17 02 11 15 11 16 6f ?? 00 00 0a 13 18 04 03 6f ?? 00 00 0a 59 13 19 11 19 13 1a 11 1a 19 31 03 19 13 1a 11 1a 16 2f 03 16 13 1a 11 04 16 5f 13 1b 11 1b 19 5d 13 1c 17 11 1b 58 19 5d 13 1d 18 11 1b 58 19 5d 13 1e 19 8d ?? ?? ?? ?? 13 1f 11 1f 16 12 18 28 ?? 00 00 0a 9c 11 1f 17 12 18 28 ?? 00 00 0a 9c 11 1f 18 12 18 28 ?? 00 00 0a 9c 11 1a 16 31 0f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}