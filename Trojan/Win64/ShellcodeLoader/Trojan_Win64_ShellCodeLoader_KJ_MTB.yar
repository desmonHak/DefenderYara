
rule Trojan_Win64_ShellCodeLoader_KJ_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeLoader.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 89 c1 49 0f af d0 48 c1 ea ?? 8d 14 52 c1 e2 ?? 29 d1 8d 50 ?? 32 14 03 48 63 c9 32 94 0c ?? ?? ?? ?? 88 14 03 48 83 c0 ?? 48 3d ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}