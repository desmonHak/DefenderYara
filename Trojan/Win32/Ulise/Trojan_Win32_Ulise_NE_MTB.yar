
rule Trojan_Win32_Ulise_NE_MTB{
	meta:
		description = "Trojan:Win32/Ulise.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 0f b7 83 ?? 00 00 00 66 85 c0 74 14 0f b7 c0 50 6a 00 e8 66 cd ?? ff 66 c7 83 } //2
		$a_03_1 = {8d 55 fc a1 30 78 51 00 e8 97 c1 ?? ff 8b 4d fc b2 01 a1 04 6c 41 00 e8 38 23 ?? ff e8 6b 9a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}