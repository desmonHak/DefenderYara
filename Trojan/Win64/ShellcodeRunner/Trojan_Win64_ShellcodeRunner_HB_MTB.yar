
rule Trojan_Win64_ShellcodeRunner_HB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 b8 4c 6f 61 64 4c 69 62 72 48 } //30
		$a_01_1 = {48 b8 49 6e 74 65 72 6e 65 } //10
		$a_01_2 = {00 64 64 72 65 48 8b cf } //20
		$a_01_3 = {00 00 48 b8 74 65 72 53 65 72 76 65 } //40
		$a_01_4 = {2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //60 搮汬䐀汬敒楧瑳牥敓癲牥
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20+(#a_01_3  & 1)*40+(#a_01_4  & 1)*60) >=100
 
}