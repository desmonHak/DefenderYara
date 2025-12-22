
rule Trojan_BAT_AsyncRat_ATR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e b7 17 da 13 07 13 06 2b 21 09 11 06 91 11 04 11 06 11 04 8e b7 5d 91 61 13 05 08 11 05 6f ?? ?? ?? 0a 00 00 11 06 17 d6 13 06 11 06 11 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ATR_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 08 e0 58 09 11 08 91 52 11 07 11 08 e0 58 47 09 11 08 91 33 e8 11 08 17 58 13 08 11 08 1e } //2
		$a_03_1 = {0d 16 13 06 2b 15 09 11 06 8f ?? 00 00 01 25 47 1f 0a 59 d2 52 11 06 17 58 13 06 11 06 6e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}