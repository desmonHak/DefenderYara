
rule Trojan_Win64_KillAV_SE_MTB{
	meta:
		description = "Trojan:Win64/KillAV.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 6f 75 72 63 65 20 65 78 74 72 61 63 74 65 64 20 74 6f 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4e 53 65 63 4b 72 6e 6c 2e 73 79 73 } //1 Resource extracted to C:\ProgramData\NSecKrnl.sys
		$a_01_1 = {57 61 74 63 68 44 6f 67 4b 69 6c 6c 65 72 2d 6d 61 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4e 53 65 63 53 6f 66 74 42 59 4f 56 44 64 6c 6c 2e 70 64 62 } //1 WatchDogKiller-main\x64\Release\NSecSoftBYOVDdll.pdb
		$a_01_2 = {52 75 6e 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e } //1 RunProcessTermination
		$a_01_3 = {44 72 69 76 65 72 73 5c 4e 53 65 63 4b 72 6e 6c 5c 4e 53 65 63 4b 72 6e 6c 5c 62 69 6e 5c 4e 53 65 63 4b 72 6e 6c 36 34 2e 70 64 62 } //1 Drivers\NSecKrnl\NSecKrnl\bin\NSecKrnl64.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}