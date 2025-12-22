
rule Trojan_Win32_ShellcodeRunner_GVE_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 6e 6f 74 65 70 61 64 2e 65 78 65 } //2 Start-Process notepad.exe
		$a_01_1 = {53 74 6f 70 2d 50 72 6f 63 65 73 73 20 2d 4e 61 6d 65 20 63 61 6c 63 75 6c 61 74 6f 72 } //1 Stop-Process -Name calculator
		$a_01_2 = {4e 65 77 2d 49 74 65 6d 20 2d 50 61 74 68 20 43 3a 5c 74 65 6d 70 20 2d 49 74 65 6d 54 79 70 65 20 44 69 72 65 63 74 6f 72 79 20 2d 46 6f 72 63 65 } //1 New-Item -Path C:\temp -ItemType Directory -Force
		$a_01_3 = {52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 20 43 3a 5c 74 65 6d 70 5c 2a 2e 74 6d 70 20 2d 46 6f 72 63 65 } //1 Remove-Item -Path C:\temp\*.tmp -Force
		$a_01_4 = {43 6f 70 79 2d 49 74 65 6d 20 2d 50 61 74 68 20 43 3a 5c 66 69 6c 65 31 2e 74 78 74 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 66 69 6c 65 32 2e 74 78 74 } //1 Copy-Item -Path C:\file1.txt -Destination C:\file2.txt
		$a_01_5 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 68 74 74 70 3a 2f 2f 65 78 61 6d 70 6c 65 2e 63 6f 6d 20 2d 4f 75 74 46 69 6c 65 20 74 65 73 74 2e 68 74 6d 6c } //1 Invoke-WebRequest -Uri http://example.com -OutFile test.html
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}