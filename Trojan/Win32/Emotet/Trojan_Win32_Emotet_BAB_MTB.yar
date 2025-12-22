
rule Trojan_Win32_Emotet_BAB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 05 03 51 04 8b c8 c1 e1 04 03 0b 33 d1 8d 0c 07 33 d1 8d bf ?? ?? ?? ?? 2b f2 83 6d 0c 01 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}