
rule HackTool_Win32_NirCmd_AMTB{
	meta:
		description = "HackTool:Win32/NirCmd!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 61 6b 65 64 2f 4e 53 75 64 6f 4c 47 2e 65 78 65 } //saked/NSudoLG.exe  1
		$a_80_1 = {73 61 6b 65 64 2f 6e 69 72 63 6d 64 2e 65 78 65 } //saked/nircmd.exe  1
		$a_80_2 = {73 61 6b 65 64 2f 63 65 63 68 6f 2e 65 78 65 } //saked/cecho.exe  1
		$a_80_3 = {73 61 6b 65 64 2f 73 61 6d 65 2e 7a 69 70 } //saked/same.zip  1
		$a_80_4 = {73 61 6b 65 64 2f 37 7a 2e 65 78 65 } //saked/7z.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}