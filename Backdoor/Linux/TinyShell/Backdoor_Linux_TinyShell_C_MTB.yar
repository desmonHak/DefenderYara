
rule Backdoor_Linux_TinyShell_C_MTB{
	meta:
		description = "Backdoor:Linux/TinyShell.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 73 68 64 5f 67 65 74 5f 66 69 6c 65 } //1 tshd_get_file
		$a_01_1 = {70 65 6c 5f 63 6c 69 65 6e 74 5f 69 6e 69 74 } //1 pel_client_init
		$a_01_2 = {70 65 6c 5f 73 65 6e 64 5f 61 6c 6c } //1 pel_send_all
		$a_01_3 = {74 73 68 64 5f 70 75 74 5f 66 69 6c 65 } //1 tshd_put_file
		$a_01_4 = {70 65 6c 5f 72 65 63 76 5f 61 6c 6c } //1 pel_recv_all
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}