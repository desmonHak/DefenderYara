
rule Trojan_Win32_Amadey_BAC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 0f af d1 33 95 ?? ?? ?? ?? 8b 45 c0 8b 8d ?? ?? ?? ?? 03 14 81 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}