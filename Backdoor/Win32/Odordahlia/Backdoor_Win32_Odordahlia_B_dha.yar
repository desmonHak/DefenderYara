
rule Backdoor_Win32_Odordahlia_B_dha{
	meta:
		description = "Backdoor:Win32/Odordahlia.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 69 6e 61 6c 5f 73 61 } //1 final_sa
		$a_01_1 = {68 74 74 70 73 5f 68 65 61 64 } //1 https_head
		$a_01_2 = {74 65 78 74 5f 73 65 6d 5f 6e 61 6d 65 } //1 text_sem_name
		$a_01_3 = {6f 76 65 72 73 65 63 73 } //1 oversecs
		$a_02_4 = {6a 02 58 c1 e0 03 6a ?? 59 66 89 4c 05 ?? 6a 02 58 c1 e0 00 6a ?? 59 66 89 4c 05 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*10) >=4
 
}