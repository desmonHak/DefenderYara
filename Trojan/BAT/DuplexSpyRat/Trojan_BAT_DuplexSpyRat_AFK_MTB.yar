
rule Trojan_BAT_DuplexSpyRat_AFK_MTB{
	meta:
		description = "Trojan:BAT/DuplexSpyRat.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 03 1b 6f ?? 01 00 0a 0c 08 39 08 00 00 00 00 07 0a 38 13 00 00 00 00 07 17 58 0b 07 28 ?? 00 00 0a 8e 69 fe 04 0d 09 2d c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}