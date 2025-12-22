
rule Trojan_Win32_SuspBoot_A{
	meta:
		description = "Trojan:Win32/SuspBoot.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {62 63 64 65 64 69 74 2e 65 78 65 } //bcdedit.exe  1
		$a_00_1 = {2d 00 76 00 } //1 -v
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}