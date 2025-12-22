
rule Trojan_Win32_Tedy_PGTL_MTB{
	meta:
		description = "Trojan:Win32/Tedy.PGTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 0c c0 e8 02 32 c8 8b 45 e0 40 88 0e 89 45 e0 3d ?? ?? ?? ?? 7c } //5
		$a_03_1 = {8b 4d e4 8a 14 32 03 c8 83 e1 ?? 32 14 39 8b 4d e0 32 d3 88 10 40 83 6d c8 01 75 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}