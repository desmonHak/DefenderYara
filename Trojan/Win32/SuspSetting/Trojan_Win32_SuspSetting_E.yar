
rule Trojan_Win32_SuspSetting_E{
	meta:
		description = "Trojan:Win32/SuspSetting.E,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 65 74 } //cmd.exe /c set  1
		$a_80_1 = {68 6f 73 74 6e 61 6d 65 2e 65 78 65 } //hostname.exe  1
		$a_80_2 = {71 70 72 6f 63 65 73 73 } //qprocess  1
		$a_80_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 65 72 } //cmd.exe /c ver  1
		$a_80_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 20 7c 20 66 69 6e 64 73 74 72 20 2f 42 20 2f 43 3a 4f 53 20 4e 61 6d 65 20 2f 43 3a 4f 53 20 56 65 72 73 69 6f 6e } //cmd.exe /c systeminfo | findstr /B /C:OS Name /C:OS Version  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=1
 
}