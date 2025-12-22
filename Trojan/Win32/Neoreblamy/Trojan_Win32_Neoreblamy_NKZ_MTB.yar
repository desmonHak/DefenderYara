
rule Trojan_Win32_Neoreblamy_NKZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 83 a5 dc fe ff ff 00 6a 04 58 } //1
		$a_01_1 = {8b 45 a0 40 89 45 a0 83 7d a0 03 7d 10 8b 45 a0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}