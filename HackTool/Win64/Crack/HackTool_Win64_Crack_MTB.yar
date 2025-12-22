
rule HackTool_Win64_Crack_MTB{
	meta:
		description = "HackTool:Win64/Crack!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 57 69 6e 64 6f 77 } //GetWindow  1
		$a_80_1 = {45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 } //Enter password  1
		$a_80_2 = {43 47 50 20 43 6f 20 26 20 6d 30 6e 6b 72 75 73 } //CGP Co & m0nkrus  1
		$a_80_3 = {41 63 72 6f 62 61 74 20 50 72 6f } //Acrobat Pro  1
		$a_80_4 = {63 72 61 63 6b 2e 65 78 65 } //crack.exe  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=5
 
}