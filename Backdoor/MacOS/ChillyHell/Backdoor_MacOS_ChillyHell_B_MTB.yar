
rule Backdoor_MacOS_ChillyHell_B_MTB{
	meta:
		description = "Backdoor:MacOS/ChillyHell.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 68 01 00 00 4d 89 cc 4d 89 c6 48 89 f3 80 39 00 0f 84 ad 00 00 00 49 89 cf 49 89 d5 0f b6 07 48 89 c1 48 d1 e9 24 01 48 89 7d b8 48 8b 57 08 48 89 d6 48 0f 44 f1 48 85 f6 } //1
		$a_01_1 = {54 61 73 6b 43 72 65 61 74 65 42 61 63 6b 43 6f 6e 6e 65 63 74 53 68 65 6c 6c } //1 TaskCreateBackConnectShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}