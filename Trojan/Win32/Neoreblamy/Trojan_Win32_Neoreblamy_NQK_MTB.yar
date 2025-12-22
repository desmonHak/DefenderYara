
rule Trojan_Win32_Neoreblamy_NQK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 ac 48 89 45 ac 83 7d ac ef } //1
		$a_03_1 = {58 6b c0 03 8b 84 05 ?? ?? ff ff 40 6a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}