
rule Trojan_Linux_Koske_A_MTB{
	meta:
		description = "Trojan:Linux/Koske.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 6f 73 6b 65 } //2 koske
		$a_01_1 = {72 65 61 64 64 69 72 } //2 readdir
		$a_01_2 = {68 69 64 65 70 72 6f 63 } //1 hideproc
		$a_01_3 = {2f 64 65 76 2f 73 68 6d 2f 2e 68 69 64 64 65 6e 70 69 64 } //1 /dev/shm/.hiddenpid
		$a_01_4 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 66 64 2f 25 64 } //1 /proc/self/fd/%d
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}