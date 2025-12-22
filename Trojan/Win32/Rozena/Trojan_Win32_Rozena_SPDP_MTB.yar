
rule Trojan_Win32_Rozena_SPDP_MTB{
	meta:
		description = "Trojan:Win32/Rozena.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 50 01 89 94 24 ?? ?? ?? ?? 0f b6 00 0f be c0 34 ff 89 c2 8b 84 24 ?? ?? ?? ?? 89 44 24 04 89 14 24 e8 ae 10 00 00 8b 84 24 ?? ?? ?? ?? 8d 50 ff 89 94 24 ?? ?? ?? ?? 85 c0 75 bd } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}