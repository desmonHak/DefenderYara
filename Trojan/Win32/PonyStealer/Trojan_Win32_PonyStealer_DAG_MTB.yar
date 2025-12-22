
rule Trojan_Win32_PonyStealer_DAG_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {5e b9 00 00 00 00 0b 08 46 31 f1 3b 8c 24 ?? ?? ?? ?? 75 } //2
		$a_01_1 = {31 30 57 83 f7 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_PonyStealer_DAG_MTB_2{
	meta:
		description = "Trojan:Win32/PonyStealer.DAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 9c 24 1c 01 00 00 50 8b 44 24 04 58 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 8b 44 24 04 58 83 c0 04 81 fa ?? ?? ?? ?? 39 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}