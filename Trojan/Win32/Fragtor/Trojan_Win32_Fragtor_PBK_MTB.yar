
rule Trojan_Win32_Fragtor_PBK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0a 8d 49 ?? 32 c3 2a 85 ?? ?? ?? ?? 88 41 ?? 83 ee ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}