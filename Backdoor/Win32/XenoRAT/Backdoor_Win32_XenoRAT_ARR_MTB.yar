
rule Backdoor_Win32_XenoRAT_ARR_MTB{
	meta:
		description = "Backdoor:Win32/XenoRAT.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 43 72 65 61 74 65 53 75 62 53 6f 63 6b 65 74 3e 64 5f 5f 37 } //2 <CreateSubSocket>d__7
		$a_01_1 = {3c 52 75 6e 43 6c 69 65 6e 74 4c 6f 6f 70 41 73 79 6e 63 3e 64 5f 5f 38 } //3 <RunClientLoopAsync>d__8
		$a_01_2 = {46 37 32 37 37 31 43 30 38 43 44 34 44 39 45 36 44 35 45 30 32 33 44 30 33 44 41 33 43 39 } //5 F72771C08CD4D9E6D5E023D03DA3C9
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*5) >=10
 
}