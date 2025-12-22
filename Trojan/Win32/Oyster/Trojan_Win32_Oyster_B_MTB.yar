
rule Trojan_Win32_Oyster_B_MTB{
	meta:
		description = "Trojan:Win32/Oyster.B!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 72 69 76 65 2e 75 73 65 72 63 6f 6e 74 65 6e 74 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 3f 69 64 3d } //1 drive.usercontent.google.com/download?id=
		$a_01_1 = {26 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 61 75 74 68 75 73 65 72 3d } //1 &export=download&authuser=
		$a_01_2 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_01_3 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 } //1 schtasks.exe /Create
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}