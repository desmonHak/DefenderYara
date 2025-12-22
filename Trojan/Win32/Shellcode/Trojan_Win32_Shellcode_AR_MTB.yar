
rule Trojan_Win32_Shellcode_AR_MTB{
	meta:
		description = "Trojan:Win32/Shellcode.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 50 01 89 94 24 ?? ?? ?? ?? 0f b6 00 0f be c0 34 ff 89 c2 8b 84 24 ?? ?? ?? ?? 89 44 24 04 89 14 24 } //30
		$a_03_1 = {8d 50 07 85 c0 0f 48 c2 c1 f8 03 0f b6 44 04 14 0f be d0 8b 84 24 ?? ?? ?? ?? 83 e0 07 89 c1 d3 fa 89 d0 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}