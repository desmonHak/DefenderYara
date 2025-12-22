
rule Backdoor_Win32_CausticDahlia_B_dha{
	meta:
		description = "Backdoor:Win32/CausticDahlia.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 5f 6e 61 6d 65 } //1 reg_name
		$a_01_1 = {72 65 67 5f 76 61 6c 75 65 } //1 reg_value
		$a_01_2 = {72 65 67 5f 63 6d 64 } //1 reg_cmd
		$a_01_3 = {74 65 78 74 5f 72 65 67 } //1 text_reg
		$a_01_4 = {63 6d 64 5f 74 6d 70 } //1 cmd_tmp
		$a_01_5 = {63 75 72 5f 64 69 72 } //1 cur_dir
		$a_01_6 = {66 69 6e 64 5f 64 61 74 61 } //1 find_data
		$a_01_7 = {66 69 6c 65 5f 6f 70 } //1 file_op
		$a_01_8 = {74 65 78 74 5f 73 68 65 6c 6c 33 32 } //1 text_shell32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}