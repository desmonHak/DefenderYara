
rule Trojan_Win32_Zenpak_GVB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 0c 0b 41 30 41 02 48 8b c7 48 f7 e1 48 c1 ea 02 48 8d 04 92 4c 2b c0 41 0f b6 44 28 05 41 30 41 03 49 83 c1 06 4b 8d 04 0a 48 3d 00 18 00 00 0f 82 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}