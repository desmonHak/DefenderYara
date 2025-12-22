
rule Trojan_Win64_MangoJuice_A_dha{
	meta:
		description = "Trojan:Win64/MangoJuice.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 4d 79 43 4d 44 4d 61 6e 61 67 65 72 40 40 } //1 .?AVMyCMDManager@@
		$a_01_1 = {2e 3f 41 56 54 43 50 4e 65 74 42 75 66 66 65 72 48 65 6c 70 65 72 40 40 } //1 .?AVTCPNetBufferHelper@@
		$a_01_2 = {2e 3f 41 56 4e 65 74 42 75 66 66 65 72 48 65 6c 70 65 72 40 40 } //1 .?AVNetBufferHelper@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}