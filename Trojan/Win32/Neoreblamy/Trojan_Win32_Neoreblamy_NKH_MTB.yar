
rule Trojan_Win32_Neoreblamy_NKH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 8b 45 e4 40 89 45 e4 83 7d e4 03 7f 30 } //1
		$a_01_1 = {eb 08 8b 45 f0 40 40 89 45 f0 83 7d f0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}