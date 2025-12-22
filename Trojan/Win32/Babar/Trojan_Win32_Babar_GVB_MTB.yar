
rule Trojan_Win32_Babar_GVB_MTB{
	meta:
		description = "Trojan:Win32/Babar.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 15 4e 40 66 00 8b f0 30 15 43 40 66 00 a0 41 40 66 00 0c 0c c0 e8 02 0f b6 c8 89 4c 24 ?? 57 db 44 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}