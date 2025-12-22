
rule Trojan_Win32_ReverseShell_CB_MTB{
	meta:
		description = "Trojan:Win32/ReverseShell.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 2e c7 85 ?? ?? ff ff 65 78 65 } //1
		$a_03_1 = {f3 ab c7 44 24 ?? ?? ?? ?? 00 c7 44 24 ?? ?? ?? ?? 00 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 8d 85 ?? ?? ff ff 89 44 24 ?? c7 04 24 00 00 00 00 e8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}