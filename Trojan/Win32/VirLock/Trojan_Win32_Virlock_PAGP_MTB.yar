
rule Trojan_Win32_Virlock_PAGP_MTB{
	meta:
		description = "Trojan:Win32/Virlock.PAGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 e9 00 00 00 00 42 46 90 47 49 83 f9 00 0f 85 e6 } //3
		$a_01_1 = {6a 40 68 00 10 00 00 68 00 98 00 00 6a 00 e8 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}