
rule Trojan_Win32_Neoreblamy_NKV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 40 6a 04 } //1
		$a_01_1 = {eb 07 8b 45 ac 40 89 45 ac 83 7d ac 03 7d 10 8b 45 ac } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}