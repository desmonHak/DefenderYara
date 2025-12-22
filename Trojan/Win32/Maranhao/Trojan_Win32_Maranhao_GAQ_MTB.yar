
rule Trojan_Win32_Maranhao_GAQ_MTB{
	meta:
		description = "Trojan:Win32/Maranhao.GAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 b8 3a 00 ?? ?? ?? ?? ?? ?? 46 02 00 0a } //8
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 b8 3a 00 ?? ?? ?? ?? ?? ?? 43 02 00 0a } //8
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*8) >=8
 
}