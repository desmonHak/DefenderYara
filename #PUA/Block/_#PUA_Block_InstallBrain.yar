
rule _#PUA_Block_InstallBrain{
	meta:
		description = "!#PUA:Block:InstallBrain,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 75 72 6c } //get_component_url  1
		$a_80_1 = {69 73 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 6f 66 66 65 72 65 64 } //is_component_offered  1
		$a_80_2 = {69 73 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 61 63 63 65 70 74 65 64 } //is_component_accepted  1
		$a_80_3 = {69 73 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 69 6e 73 74 61 6c 6c 65 64 } //is_component_installed  1
		$a_80_4 = {67 65 74 5f 63 6f 75 6e 74 5f 6f 66 66 65 72 5f 70 61 67 65 73 } //get_count_offer_pages  1
		$a_80_5 = {70 61 67 65 5f 6f 66 66 65 72 } //page_offer  1
		$a_80_6 = {73 65 74 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 63 72 79 70 74 65 64 } //set_component_crypted  1
		$a_80_7 = {64 65 63 72 79 70 74 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 66 69 6c 65 } //decrypt_component_file  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}