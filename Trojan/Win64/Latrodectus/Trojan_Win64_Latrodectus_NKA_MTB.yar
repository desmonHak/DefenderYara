
rule Trojan_Win64_Latrodectus_NKA_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.NKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {5c 43 3a 5c 54 45 4d 50 5c 4c 61 74 72 6f 64 65 63 74 75 73 2e 6c 6f 67 } //2 \C:\TEMP\Latrodectus.log
		$a_81_1 = {55 70 64 61 74 65 72 54 61 67 2e 64 6c 6c } //1 UpdaterTag.dll
		$a_81_2 = {4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtMapViewOfSection
		$a_81_3 = {4e 74 43 72 65 61 74 65 53 65 63 74 69 6f 6e } //1 NtCreateSection
		$a_81_4 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 rundll32.exe
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 20 66 69 6c 65 } //1 Download file
		$a_81_6 = {72 65 67 73 76 72 33 32 2e 65 78 65 } //1 regsvr32.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}