
rule Trojan_Win64_ShellcodeRunner_YAH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 bb 76 6a 40 83 46 aa bb 5c 48 b9 73 eb aa 92 e7 77 a1 64 } //1
		$a_01_1 = {4d 50 49 5f 49 6e 69 74 } //1 MPI_Init
		$a_01_2 = {4d 50 49 5f 57 74 69 63 6b } //1 MPI_Wtick
		$a_01_3 = {6d 73 6d 70 69 2e 64 6c 6c } //1 msmpi.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}