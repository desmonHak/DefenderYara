
rule Backdoor_Linux_Reverseshell_SR4{
	meta:
		description = "Backdoor:Linux/Reverseshell.SR4,SIGNATURE_TYPE_ELFHSTR_EXT,39 00 39 00 09 00 00 "
		
	strings :
		$a_80_0 = {55 73 61 67 65 3a 20 25 73 20 3c 72 65 66 6c 65 63 74 20 69 70 3e 20 3c 70 6f 72 74 3e } //Usage: %s <reflect ip> <port>  50
		$a_80_1 = {2f 62 69 6e 2f 73 68 } ///bin/sh  2
		$a_80_2 = {2f 62 69 6e 2f 62 61 73 68 } ///bin/bash  2
		$a_81_3 = {73 6f 63 6b 65 74 } //1 socket
		$a_81_4 = {65 78 65 63 6c } //1 execl
		$a_81_5 = {65 78 65 63 76 65 } //1 execve
		$a_81_6 = {68 74 6f 6e 73 } //1 htons
		$a_81_7 = {69 6e 65 74 5f 70 74 6f 6e } //1 inet_pton
		$a_81_8 = {64 75 70 32 } //1 dup2
	condition:
		((#a_80_0  & 1)*50+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=57
 
}