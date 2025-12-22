
rule VirTool_Win64_SearchSyscall_A{
	meta:
		description = "VirTool:Win64/SearchSyscall.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d9 66 c7 44 24 ?? 0f 05 c6 44 24 ?? c3 45 33 d2 4d 63 da 48 8d 4c 24 ?? 4c 03 db 41 b8 03 00 00 00 49 8b d3 e8 ?? ?? ?? ?? 85 c0 74 0d 41 ff c2 41 83 fa 20 7c da 33 c0 eb 03 49 8b c3 48 83 c4 20 5b c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}