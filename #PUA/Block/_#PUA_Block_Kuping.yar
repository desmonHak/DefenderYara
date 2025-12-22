
rule _#PUA_Block_Kuping{
	meta:
		description = "!#PUA:Block:Kuping,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 65 73 6b 74 6f 70 42 61 63 6b 67 72 6f 75 6e 64 5c 53 68 65 6c 6c 5c 4b 75 70 69 6e 67 5c 43 6f 6d 6d 61 6e 64 } //DesktopBackground\Shell\Kuping\Command  1
		$a_02_1 = {5c 6b 75 70 69 6e 67 5f 76 [0-02] 2e 65 78 65 2c 25 64 } //1
		$a_00_2 = {25 73 5c 4b 70 49 6e 73 74 61 6c 6c 54 68 65 6d 65 2e 65 78 65 } //1 %s\KpInstallTheme.exe
		$a_00_3 = {68 75 61 79 75 6b 65 6a 69 6b 75 70 69 6e 67 } //1 huayukejikuping
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#PUA_Block_Kuping_2{
	meta:
		description = "!#PUA:Block:Kuping,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {4b 50 54 6f 6f 6c 42 61 72 53 69 6c 65 6e 63 65 2e 65 78 65 } //1 KPToolBarSilence.exe
		$a_00_1 = {55 6e 69 76 65 72 73 61 6c 4d 69 6e 69 2e 65 78 65 } //1 UniversalMini.exe
		$a_00_2 = {4b 50 34 4d 69 6e 69 2e 65 78 65 } //1 KP4Mini.exe
		$a_02_3 = {68 74 74 70 3a 2f 2f [0-0f] 2e 6b 75 70 69 6e 67 2e 63 63 2f } //1
		$a_00_4 = {6b 70 6c 69 6e 6b 2e 65 78 65 } //1 kplink.exe
		$a_00_5 = {63 6f 6e 66 69 67 2e 30 35 35 31 66 73 2e 63 6f 6d 2f 50 75 62 6c 69 63 2f 43 6f 6e 66 69 67 73 2f 75 6e 69 6e 73 74 61 6c 6c 5f 62 65 67 69 6e 2e 68 74 6d 6c } //-10 config.0551fs.com/Public/Configs/uninstall_begin.html
		$a_00_6 = {63 6f 6e 66 69 67 2e 30 35 35 31 66 73 2e 63 6f 6d 2f 50 75 62 6c 69 63 2f 43 6f 6e 66 69 67 73 2f 75 6e 69 6e 73 74 61 6c 6c 5f 65 6e 64 2e 68 74 6d 6c } //-10 config.0551fs.com/Public/Configs/uninstall_end.html
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*-10+(#a_00_6  & 1)*-10) >=4
 
}