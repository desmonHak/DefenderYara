
rule Trojan_Win32_GCleaner_PGGE_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 01 1f b8 8a a5 08 00 03 45 c4 03 c3 03 c6 89 45 b0 c7 45 a0 16 19 00 00 6a 00 e8 ?? ?? ?? ?? 8b 55 b0 03 55 a0 81 ea 16 19 00 00 2b d0 03 d6 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 03 d6 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 03 f2 6a 00 e8 ?? ?? ?? ?? 2b f0 31 37 83 c3 04 83 c7 04 3b 5d c8 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}