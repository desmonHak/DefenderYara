
rule Trojan_Win32_SusPrivChecks_C{
	meta:
		description = "Trojan:Win32/SusPrivChecks.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 71 75 65 72 79 } //reg.exe query  1
		$a_80_1 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4e 6c 73 5c 4c 61 6e 67 75 61 67 65 } //HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}