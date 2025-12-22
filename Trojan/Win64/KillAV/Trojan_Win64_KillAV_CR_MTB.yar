
rule Trojan_Win64_KillAV_CR_MTB{
	meta:
		description = "Trojan:Win64/KillAV.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 3a 06 01 00 48 63 c8 49 8b c6 48 f7 e1 48 c1 ea 04 48 6b c2 34 48 2b c8 0f b6 84 29 78 51 04 00 88 84 2b d0 ec 04 00 48 ff c3 48 3b df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}