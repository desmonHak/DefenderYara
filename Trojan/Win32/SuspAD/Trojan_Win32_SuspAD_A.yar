
rule Trojan_Win32_SuspAD_A{
	meta:
		description = "Trojan:Win32/SuspAD.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_80_0 = {6e 6c 74 65 73 74 2e 65 78 65 20 2f 64 63 6c 69 73 74 3a } //nltest.exe /dclist:  1
		$a_80_1 = {6e 6c 74 65 73 74 2e 65 78 65 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 20 2f 61 6c 6c 5f 74 72 75 73 74 73 } //nltest.exe /domain_trusts /all_trusts  1
		$a_80_2 = {6e 65 74 2e 65 78 65 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 } //net.exe localgroup administrators  1
		$a_80_3 = {77 68 6f 61 6d 69 20 2f 67 72 6f 75 70 73 } //whoami /groups  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=1
 
}