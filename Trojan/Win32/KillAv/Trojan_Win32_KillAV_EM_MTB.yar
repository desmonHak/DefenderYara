
rule Trojan_Win32_KillAV_EM_MTB{
	meta:
		description = "Trojan:Win32/KillAV.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 4d 0c 76 10 8b 45 08 8a 55 10 03 c1 28 10 41 3b 4d 0c 72 f0 } //3
		$a_81_1 = {52 65 63 79 63 6c 65 72 5c 61 61 2e 74 78 74 } //1 Recycler\aa.txt
		$a_81_2 = {41 6e 74 69 76 75 73 54 79 70 65 20 3d 20 25 64 20 50 72 6f 63 65 73 73 4e 61 6d 65 20 3d 20 25 73 } //1 AntivusType = %d ProcessName = %s
		$a_81_3 = {42 65 67 69 6e 20 57 72 69 74 65 20 53 68 65 6c 6c 43 6f 64 65 20 46 69 6c 65 } //1 Begin Write ShellCode File
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}