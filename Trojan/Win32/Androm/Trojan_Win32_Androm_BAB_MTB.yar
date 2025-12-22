
rule Trojan_Win32_Androm_BAB_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8a 00 34 f7 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 71 ?? ?? ?? ?? ?? ?? 83 c4 08 5a 88 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}