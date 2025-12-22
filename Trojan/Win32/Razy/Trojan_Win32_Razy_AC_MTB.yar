
rule Trojan_Win32_Razy_AC_MTB{
	meta:
		description = "Trojan:Win32/Razy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 53 57 56 83 e4 f8 81 ec 88 00 00 00 8b 45 08 31 c9 8b 54 24 78 8b 74 24 7c c7 44 24 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}