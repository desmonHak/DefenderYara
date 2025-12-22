
rule Trojan_Win32_DiskWriter_ADB_MTB{
	meta:
		description = "Trojan:Win32/DiskWriter.ADB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8b c8 c1 fa 10 c1 f9 08 0a d1 8b c8 c1 f9 07 0a d1 0f b6 c8 f6 d2 22 d0 0f b6 d2 0f af d1 88 14 38 40 3b c6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}