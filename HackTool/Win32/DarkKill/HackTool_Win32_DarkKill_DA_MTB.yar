
rule HackTool_Win32_DarkKill_DA_MTB{
	meta:
		description = "HackTool:Win32/DarkKill.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 64 61 72 6b 2d 6b 69 6c 6c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 64 61 72 6b 2e 70 64 62 } //10 \dark-kill\x64\Release\dark.pdb
		$a_81_1 = {5d 20 70 72 6f 63 65 73 73 20 77 69 74 68 20 50 49 44 3a 20 25 75 20 6b 69 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 ] process with PID: %u killed successfully
		$a_81_2 = {5d 20 44 72 69 76 65 72 20 6c 6f 61 64 65 64 21 } //1 ] Driver loaded!
		$a_81_3 = {5d 20 42 6c 6f 63 6b 69 6e 67 20 63 72 65 61 74 69 6f 6e 20 6f 66 20 25 77 73 } //1 ] Blocking creation of %ws
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}