
rule Trojan_Win32_SuspWMI_A{
	meta:
		description = "Trojan:Win32/SuspWMI.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {69 66 28 28 47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 2d 63 6c 61 73 73 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 29 2e 50 61 72 74 4f 66 44 6f 6d 61 69 6e 29 } //if((Get-WmiObject -class Win32_ComputerSystem).PartOfDomain)  1
		$a_80_2 = {28 28 47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 2d 63 6c 61 73 73 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 29 2e 44 6f 6d 61 69 6e 29 } //((Get-WmiObject -class Win32_ComputerSystem).Domain)  1
		$a_80_3 = {67 77 6d 69 20 77 69 6e 33 32 5f 67 72 6f 75 70 20 2d 46 69 6c 74 65 72 } //gwmi win32_group -Filter  1
		$a_80_4 = {44 6f 6d 61 69 6e 3d } //Domain=  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}