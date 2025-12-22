
rule Trojan_Win32_Neoreblamy_NPR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {d0 40 89 45 d0 83 7d d0 02 7d 10 8b 45 d0 } //2
		$a_01_1 = {8b 45 f8 48 89 45 f8 83 7d f8 e3 } //1
		$a_01_2 = {eb 07 8b 45 ac 48 89 45 ac 83 7d ac e8 } //1
		$a_01_3 = {8b 45 b0 40 89 45 b0 83 7d b0 03 7d 10 8b 45 b0 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=3
 
}