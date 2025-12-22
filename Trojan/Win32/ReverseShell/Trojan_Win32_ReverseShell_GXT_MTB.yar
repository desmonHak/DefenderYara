
rule Trojan_Win32_ReverseShell_GXT_MTB{
	meta:
		description = "Trojan:Win32/ReverseShell.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 85 50 fe ff ff 89 44 24 04 8b 45 f0 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 0c 85 c0 } //5
		$a_03_1 = {ff d0 83 ec 18 89 45 f0 66 c7 85 ?? ?? ?? ?? 02 00 8b 45 f4 0f b7 c0 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 04 66 89 85 52 fe ff ff c7 04 24 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff d0 83 ec 04 89 85 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}