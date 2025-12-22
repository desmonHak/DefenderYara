
rule Trojan_Win32_ICLoader_GZF_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8d 0c c5 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0b c8 33 d0 89 4d f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_ICLoader_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 cf c1 ca 00 00 ee 01 fb c1 ce ?? 01 e9 8b 7c 24 ?? 31 ee } //5
		$a_01_1 = {31 f9 c1 ca 05 00 00 89 74 24 1c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}