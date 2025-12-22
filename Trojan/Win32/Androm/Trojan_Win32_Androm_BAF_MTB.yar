
rule Trojan_Win32_Androm_BAF_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 45 cc 2b c2 83 c0 04 89 45 ec ff 75 fc b9 21 00 00 00 ff 75 f8 b9 21 00 00 00 ff 75 f0 b9 21 00 00 00 ff 75 f4 b9 21 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAF_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fa 03 fb 03 f8 c7 45 ?? 16 19 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d ?? 81 ef 16 19 00 00 2b f8 6a 00 e8 [0-1f] 03 f8 31 3e 83 c3 04 83 c6 04 3b 5d ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}