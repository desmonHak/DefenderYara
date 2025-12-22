
rule Trojan_Win32_Tepfer_BAG_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 00 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}