
rule Trojan_Win32_Virlock_ARAC_MTB{
	meta:
		description = "Trojan:Win32/Virlock.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 e9 15 00 00 00 } //2
		$a_01_1 = {83 f9 00 90 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Virlock_ARAC_MTB_2{
	meta:
		description = "Trojan:Win32/Virlock.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 e9 } //2
		$a_01_1 = {8a 06 32 c2 e9 } //2
		$a_01_2 = {88 07 90 42 46 90 47 49 83 f9 00 90 e9 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=5
 
}