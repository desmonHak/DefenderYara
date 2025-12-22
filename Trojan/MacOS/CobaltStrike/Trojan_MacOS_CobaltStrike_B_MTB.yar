
rule Trojan_MacOS_CobaltStrike_B_MTB{
	meta:
		description = "Trojan:MacOS/CobaltStrike.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2f 63 30 6d 64 2e 70 61 72 73 65 43 6f 6d 6d 61 6e 64 55 70 6c 6f 61 64 } //1 main/c0md.parseCommandUpload
		$a_01_1 = {6d 61 69 6e 2f 63 30 6d 64 2e 53 70 61 77 6e 41 6e 64 49 6e 6a 65 63 74 44 6c 6c } //1 main/c0md.SpawnAndInjectDll
		$a_01_2 = {6d 61 69 6e 2f 63 30 6d 64 2e 4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 main/c0md.KillProcess
		$a_01_3 = {6d 61 69 6e 2f 63 30 6d 64 2e 53 74 65 61 6c 54 6f 6b 65 6e } //1 main/c0md.StealToken
		$a_01_4 = {6d 61 69 6e 2f 63 30 6d 64 2e 70 61 72 73 65 43 6f 6d 6d 61 6e 64 53 68 65 6c 6c } //1 main/c0md.parseCommandShell
		$a_01_5 = {6d 61 69 6e 2f 63 30 6d 64 2e 55 70 6c 6f 61 64 } //1 main/c0md.Upload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}