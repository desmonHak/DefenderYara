
rule Trojan_Win32_SuspDirectory_MK{
	meta:
		description = "Trojan:Win32/SuspDirectory.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {66 6f 72 20 25 47 20 69 6e 20 28 2e 74 78 74 29 } //for %G in (.txt)  1
		$a_80_2 = {64 6f 20 66 6f 72 66 69 6c 65 73 20 2f 70 } //do forfiles /p  1
		$a_80_3 = {2f 73 20 2f 4d 20 2a 25 47 20 2f 43 } ///s /M *%G /C  1
		$a_80_4 = {63 6d 64 20 2f 63 20 65 63 68 6f 20 40 50 41 54 48 } //cmd /c echo @PATH  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}