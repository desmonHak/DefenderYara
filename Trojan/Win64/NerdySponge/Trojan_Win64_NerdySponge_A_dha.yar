
rule Trojan_Win64_NerdySponge_A_dha{
	meta:
		description = "Trojan:Win64/NerdySponge.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 75 74 64 6f 77 6e 53 51 4c 50 72 6f 63 65 73 73 65 73 } //1 ShutdownSQLProcesses
		$a_01_1 = {37 39 39 32 32 30 39 37 38 32 3a 41 41 47 47 49 71 37 34 75 4c 76 55 41 53 30 6b 4f 38 7a 55 73 4b 4d 47 49 4a 6e 43 70 47 66 67 38 77 38 } //1 7992209782:AAGGIq74uLvUAS0kO8zUsKMGIJnCpGfg8w8
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 77 61 6c 6b 20 70 61 74 68 20 25 73 3a 20 25 76 } //1 Failed to walk path %s: %v
		$a_01_3 = {f0 9f 93 b8 20 53 63 72 65 65 6e 73 68 6f 74 0a f0 9f 91 a4 20 55 73 65 72 3a 20 25 73 0a f0 9f 92 bb 20 43 6f 6d 70 75 74 65 72 3a 20 25 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}