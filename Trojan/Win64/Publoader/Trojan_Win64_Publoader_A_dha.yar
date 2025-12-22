
rule Trojan_Win64_Publoader_A_dha{
	meta:
		description = "Trojan:Win64/Publoader.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 72 72 6f 72 3a 20 46 69 6c 65 20 43 6f 72 72 75 70 74 65 64 } //1 Error: File Corrupted
		$a_81_1 = {54 68 65 20 50 44 46 20 66 69 6c 65 20 69 73 20 63 6f 72 72 75 70 74 65 64 2e 20 50 6c 65 61 73 65 20 72 65 73 74 61 72 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 74 6f 20 74 72 79 20 61 67 61 69 6e 2e } //1 The PDF file is corrupted. Please restart your computer to try again.
		$a_81_2 = {68 65 6c 70 65 72 5f 70 72 6f 63 65 73 73 2e 65 78 65 20 4e 56 49 44 49 41 47 65 46 6f 72 63 65 } //1 helper_process.exe NVIDIAGeForce
		$a_81_3 = {4d 65 72 79 20 61 6c 74 69 6f 6e 20 66 61 69 6c 65 64 } //1 Mery altion failed
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}