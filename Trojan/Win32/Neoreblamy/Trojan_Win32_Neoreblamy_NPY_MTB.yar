
rule Trojan_Win32_Neoreblamy_NPY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d0 40 89 45 d0 83 7d d0 ?? 7d 10 8b 45 d0 } //1
		$a_03_1 = {6a 18 58 6b c0 07 8d 84 05 ?? ?? ff ff 6a 04 59 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}