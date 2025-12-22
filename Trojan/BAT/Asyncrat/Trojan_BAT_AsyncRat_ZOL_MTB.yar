
rule Trojan_BAT_AsyncRat_ZOL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ZOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 1f 64 fe 0e 06 00 20 60 00 00 00 20 26 aa 62 2b 20 0f fd 48 2b 61 20 29 57 2a 00 40 10 00 00 00 20 02 00 00 00 fe 0e 06 00 fe ?? 18 00 00 01 58 00 fe 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}