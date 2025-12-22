
rule Trojan_Win32_Stealer_ARR_MTB{
	meta:
		description = "Trojan:Win32/Stealer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0b 11 0c 9a 13 0d 11 0d 28 ?? ?? ?? ?? 18 fe 02 13 0e 11 0e 2c 40 11 0d } //15
		$a_01_1 = {13 06 08 11 04 11 06 6c 11 05 6c 5b a1 11 04 17 d6 13 04 11 04 09 31 c7 } //5
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}