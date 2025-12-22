
rule Trojan_Win32_SmokeLoader_BG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 32 45 0b 8b 4d f0 88 44 15 fc 88 4d fd 85 db 74 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}