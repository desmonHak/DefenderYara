
rule Trojan_Win64_DllHijack_GDX_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d2 48 8d 05 ?? ?? ?? ?? 31 c9 49 39 d7 ?? ?? 44 8a 04 01 45 32 04 16 41 c0 c0 04 45 88 04 16 48 ff c2 ff c1 83 e1 0f } //5
		$a_01_1 = {6a 40 41 59 31 c9 4c 89 fa 41 b8 00 30 00 00 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}