
rule Trojan_Win32_Neoreblamy_NKS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 58 c1 e0 00 8b 84 05 54 ff ff ff 48 6a 04 59 } //1
		$a_01_1 = {eb 07 8b 45 d0 40 89 45 d0 83 7d d0 02 7d 10 8b 45 d0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}