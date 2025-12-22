
rule Trojan_Win32_Ghostsocks_AGK_MTB{
	meta:
		description = "Trojan:Win32/Ghostsocks.AGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 54 24 14 8b 4c 24 14 0f b6 05 ?? ?? ?? ?? 02 c1 a2 ?? ?? ?? ?? 0f b6 04 32 42 8a 0d ?? ?? ?? ?? 32 c8 88 0d ?? ?? ?? ?? 80 3c 32 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}