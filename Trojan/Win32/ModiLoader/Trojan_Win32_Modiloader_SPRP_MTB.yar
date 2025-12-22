
rule Trojan_Win32_Modiloader_SPRP_MTB{
	meta:
		description = "Trojan:Win32/Modiloader.SPRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 04 50 6a 04 68 ?? ?? ?? ?? 8d 44 24 0c 50 6a 00 e8 43 34 fb ff 8b c3 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}