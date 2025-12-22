
rule Trojan_Win32_Lauri_ALI_MTB{
	meta:
		description = "Trojan:Win32/Lauri.ALI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 61 75 72 69 43 5c 6b 6f 6c 2e 70 61 73 } //2 LauriC\kol.pas
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {66 69 6c 65 30 61 30 2e 64 61 74 } //3 file0a0.dat
		$a_01_3 = {74 65 6d 70 30 61 31 2e 65 78 65 } //4 temp0a1.exe
		$a_01_4 = {56 49 52 55 53 3a 20 56 49 52 5c 4c 61 75 72 69 2e 49 49 49 } //5 VIRUS: VIR\Lauri.III
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5) >=15
 
}