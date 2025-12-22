
rule Trojan_Win32_Virlock_NE_MTB{
	meta:
		description = "Trojan:Win32/Virlock.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 06 32 c2 88 07 [0-0e] 83 f9 00 0f } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}