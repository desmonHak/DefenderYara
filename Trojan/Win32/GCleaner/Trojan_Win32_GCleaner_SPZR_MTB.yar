
rule Trojan_Win32_GCleaner_SPZR_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.SPZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 01 1e 8b 7d d8 03 7d a4 03 fb 03 f8 c7 45 b8 ?? ?? ?? ?? 6a 00 e8 01 3b fa ff 03 7d b8 81 ef ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}