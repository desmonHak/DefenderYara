
rule Trojan_Win32_Lazy_GVH_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 14 8b 74 24 10 8b ce b8 ?? ?? ?? ?? 83 e1 07 ba ?? ?? ?? ?? c1 e1 03 e8 14 40 00 00 30 04 3e 83 c6 01 83 d3 00 75 05 83 fe 0f 72 d9 } //2
		$a_01_1 = {80 f9 40 73 15 80 f9 20 73 06 0f ad d0 d3 ea } //1
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}