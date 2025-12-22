
rule Trojan_Win64_ShellcodeLoader_SYJ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.SYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 3c 48 89 fb 89 c1 01 f0 99 41 f7 f9 48 63 c2 8a 14 04 48 89 c6 88 14 3c 88 0c 04 02 0c 3c 0f b6 c9 8a 04 0c 43 30 04 02 49 ff c0 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}