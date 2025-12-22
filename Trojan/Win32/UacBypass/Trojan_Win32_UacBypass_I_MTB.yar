
rule Trojan_Win32_UacBypass_I_MTB{
	meta:
		description = "Trojan:Win32/UacBypass.I!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //1 reg.exe
		$a_00_1 = {61 00 64 00 64 00 } //1 add
		$a_00_2 = {68 00 6b 00 63 00 75 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 63 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 2d 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 hkcu\software\classes\ms-settings\shell\open\command
		$a_00_3 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 } //1 c:\windows\system32
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}