
rule Trojan_Linux_PAMBackdoor_B_MTB{
	meta:
		description = "Trojan:Linux/PAMBackdoor.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 5f 70 68 72 61 73 65 } //2 decrypt_phrase
		$a_01_1 = {69 6e 69 74 5f 70 68 72 61 73 65 73 } //2 init_phrases
		$a_01_2 = {6f 5f 70 61 6d 5f 61 75 74 68 65 6e 74 69 63 61 74 65 } //1 o_pam_authenticate
		$a_01_3 = {6f 5f 70 61 6d 5f 6f 70 65 6e 5f 73 65 73 73 69 6f 6e } //1 o_pam_open_session
		$a_01_4 = {73 73 68 64 5b 25 64 5d } //1 sshd[%d]
		$a_01_5 = {2f 70 72 6f 63 2f 25 73 2f 63 6d 64 6c 69 6e 65 } //1 /proc/%s/cmdline
		$a_01_6 = {2f 70 72 6f 63 2f 25 73 2f 65 6e 76 69 72 6f 6e } //1 /proc/%s/environ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}