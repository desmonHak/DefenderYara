
rule Trojan_Win32_SusValakReg_A{
	meta:
		description = "Trojan:Win32/SusValakReg.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 } //powershell.exe   1
		$a_80_1 = {4e 65 77 2d 49 74 65 6d 20 2d 50 61 74 68 } //New-Item -Path  1
		$a_80_2 = {48 4b 43 55 3a 5c 53 6f 66 74 77 61 72 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 43 6f 6e 74 61 69 6e 65 72 5c 41 70 70 73 77 36 34 5c 63 32 73 65 72 76 65 72 } //HKCU:\Software\ApplicationContainer\Appsw64\c2server  1
		$a_80_3 = {20 2d 56 61 6c 75 65 20 } // -Value   1
		$a_80_4 = {2e 63 61 62 } //.cab  1
		$a_80_5 = {2d 46 6f 72 63 65 } //-Force  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}