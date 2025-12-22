
rule Trojan_BAT_VenomRat_SK_MTB{
	meta:
		description = "Trojan:BAT/VenomRat.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {d2 13 04 03 09 03 8e 69 5d 91 13 05 08 09 20 00 01 00 00 11 04 58 11 05 59 20 00 01 00 00 5d d1 9d 09 17 58 0d 09 07 } //2
		$a_01_1 = {61 6d 61 6d 61 6d 2e 65 78 65 } //2 amamam.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}