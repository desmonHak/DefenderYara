
rule Trojan_Linux_ProcessHider_SR7{
	meta:
		description = "Trojan:Linux/ProcessHider.SR7,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_80_0 = {68 69 64 65 5f 64 65 6d 6f } //hide_demo  2
		$a_80_1 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 66 64 2f 25 64 } ///proc/self/fd/%d  2
		$a_80_2 = {2f 70 72 6f 63 2f 25 73 2f 73 74 61 74 } ///proc/%s/stat  2
		$a_80_3 = {70 72 6f 63 65 73 73 5f 74 6f 5f 66 69 6c 74 65 72 } //process_to_filter  2
		$a_80_4 = {6f 72 69 67 69 6e 61 6c 5f 72 65 61 64 64 69 72 } //original_readdir  2
		$a_80_5 = {67 65 74 5f 64 69 72 5f 6e 61 6d 65 } //get_dir_name  2
		$a_80_6 = {67 65 74 5f 70 72 6f 63 65 73 73 5f 6e 61 6d 65 } //get_process_name  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=14
 
}