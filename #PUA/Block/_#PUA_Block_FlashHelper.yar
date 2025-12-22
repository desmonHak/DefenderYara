
rule _#PUA_Block_FlashHelper{
	meta:
		description = "!#PUA:Block:FlashHelper,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {46 6c 61 73 68 48 65 6c 70 65 72 53 65 72 76 69 63 65 2e 65 78 65 } //FlashHelperService.exe  1
		$a_80_1 = {66 6c 61 73 68 70 6c 61 79 65 72 61 78 5f 69 6e 73 74 61 6c 6c 5f 63 6e 2e 65 78 65 } //flashplayerax_install_cn.exe  1
		$a_80_2 = {70 65 70 66 6c 61 73 68 70 6c 61 79 65 72 } //pepflashplayer  1
		$a_80_3 = {4d 61 63 72 6f 6d 65 64 69 61 } //Macromedia  1
		$a_80_4 = {6c 6f 70 65 6e 5f 6d 69 6e 69 5f 74 69 6d 65 } //lopen_mini_time  1
		$a_80_5 = {46 6c 61 73 68 48 65 6c 70 65 72 4d 69 6e 69 } //FlashHelperMini  1
		$a_80_6 = {74 6f 6e 67 6a 69 2e 66 6c 61 73 68 2e 63 6e } //tongji.flash.cn  1
		$a_80_7 = {6d 69 6e 69 2e 66 66 6e 65 77 73 2e 63 6e } //mini.ffnews.cn  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}