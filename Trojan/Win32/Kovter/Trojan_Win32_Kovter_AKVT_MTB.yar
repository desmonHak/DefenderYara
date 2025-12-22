
rule Trojan_Win32_Kovter_AKVT_MTB{
	meta:
		description = "Trojan:Win32/Kovter.AKVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 52 50 8b c6 c1 e0 02 99 03 04 24 13 54 24 04 83 c4 08 03 04 24 13 54 24 04 83 c4 08 8b 08 03 4d fc 81 39 4c 6f 61 64 75 56 8d 41 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}