
rule _#PUA_Block_VkDJ_BundleInstaller{
	meta:
		description = "!#PUA:Block:VkDJ_BundleInstaller,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {43 48 45 43 4b 41 55 54 4f 53 54 41 52 54 56 4b 44 4a 5f 58 50 } //CHECKAUTOSTARTVKDJ_XP  1
		$a_80_1 = {4f 4e 59 41 4e 44 45 58 41 43 54 49 56 41 54 45 } //ONYANDEXACTIVATE  1
		$a_80_2 = {56 2d 4b 5f 44 2d 4a 2e 65 78 65 } //V-K_D-J.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule _#PUA_Block_VkDJ_BundleInstaller_2{
	meta:
		description = "!#PUA:Block:VkDJ_BundleInstaller,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {44 6a 4c 6f 61 64 65 72 2e 65 78 65 } //1 DjLoader.exe
		$a_00_1 = {56 6b 6f 6e 74 61 6b 74 65 20 44 4a 20 49 6e 73 74 61 6c 6c 65 72 } //1 Vkontakte DJ Installer
		$a_00_2 = {59 41 42 52 4f 57 53 45 52 } //1 YABROWSER
		$a_80_3 = {79 61 6e 64 65 78 2e 72 75 } //yandex.ru  1
		$a_80_4 = {73 6f 66 74 2e 79 61 6e 64 65 78 2e 72 75 2f 64 69 73 74 72 69 62 75 74 69 6f 6e 2f } //soft.yandex.ru/distribution/  1
		$a_80_5 = {63 6c 69 65 6e 74 2e 63 6f 6e 66 69 67 2f 3f 61 70 70 3d 76 6b 5f 64 6f 77 6e 6c 6f 61 64 65 72 26 66 6f 72 6d 61 74 3d 78 6d 6c } //client.config/?app=vk_downloader&format=xml  1
		$a_80_6 = {64 6c 67 5f 79 61 6e 64 65 78 5f 73 65 74 75 70 5f 62 67 } //dlg_yandex_setup_bg  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}