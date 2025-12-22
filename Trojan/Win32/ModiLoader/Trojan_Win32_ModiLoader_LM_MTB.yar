
rule Trojan_Win32_ModiLoader_LM_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ac 3b 45 a8 73 ?? 8b 45 a8 31 45 ac 8b 45 ac 31 45 a8 8b 45 a8 31 45 ac } //20
		$a_01_1 = {8d 04 b6 8b 44 c7 08 89 45 ac 8d 04 b6 8b 44 c7 10 89 45 a8 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}