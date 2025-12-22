
rule Trojan_Win32_ICLoader_GSY_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 f9 c1 ca 05 00 00 89 74 24 } //5
		$a_01_1 = {31 cf c1 ca 06 00 00 01 fb c1 ce 09 } //5
		$a_01_2 = {8b 7c 24 08 31 ee 89 00 00 04 31 fd c1 ce } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}