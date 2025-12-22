
rule Trojan_Win32_Androm_BAE_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 16 0f b6 44 10 ff 33 07 5a 88 02 ff 06 4b 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAE_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b 45 c8 31 30 83 c3 04 83 45 c8 04 3b 5d c4 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}