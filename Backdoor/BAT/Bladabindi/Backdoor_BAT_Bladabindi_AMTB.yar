
rule Backdoor_BAT_Bladabindi_AMTB{
	meta:
		description = "Backdoor:BAT/Bladabindi!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_80_0 = {6b 65 79 5f 6c 6f 67 67 65 72 5f 4c 6f 61 64 } //key_logger_Load  1
		$a_80_1 = {53 70 79 4e 6f 74 65 5f 41 63 74 69 76 61 74 65 64 } //SpyNote_Activated  1
		$a_80_2 = {50 61 79 6c 6f 61 64 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d 5f 43 6c 69 63 6b } //PayloadToolStripMenuItem_Click  1
		$a_80_3 = {4c 6f 67 73 53 70 79 4e 6f 74 65 } //LogsSpyNote  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=4
 
}