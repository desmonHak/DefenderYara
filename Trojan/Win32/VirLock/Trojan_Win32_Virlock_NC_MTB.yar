
rule Trojan_Win32_Virlock_NC_MTB{
	meta:
		description = "Trojan:Win32/Virlock.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 c2 88 07 [0-04] 49 83 f9 00 } //2
		$a_03_1 = {8a 06 32 c2 88 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 07 8b f8 } //2
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}