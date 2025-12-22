
rule Trojan_Win32_Neoreblamy_NKM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e0 48 89 45 e0 83 7d e0 fc } //1
		$a_01_1 = {07 8b 45 c4 40 89 45 c4 83 7d c4 02 7d 16 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}