
rule _#PUA_Block_OnePlatform{
	meta:
		description = "!#PUA:Block:OnePlatform,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_80_0 = {64 69 37 65 31 6a 35 66 31 70 6c 66 6f } //di7e1j5f1plfo  2
		$a_80_1 = {61 66 78 77 69 6e 32 2e 69 6e } //afxwin2.in  1
		$a_80_2 = {66 69 6c 65 63 6f 72 65 2e 63 70 70 } //filecore.cpp  1
		$a_80_3 = {54 4f 4f 4c 42 41 52 5f 50 4f 50 55 50 4d 45 4e 55 } //TOOLBAR_POPUPMENU  1
		$a_80_4 = {41 46 58 5f 57 4d 5f 41 46 54 45 52 5f 54 41 53 4b 42 41 52 5f 41 43 54 49 56 41 54 45 } //AFX_WM_AFTER_TASKBAR_ACTIVATE  1
		$a_80_5 = {41 70 70 57 69 7a 61 72 64 2d 47 65 6e 65 72 61 74 65 64 } //AppWizard-Generated  1
		$a_80_6 = {51 75 69 63 6b 20 41 63 63 65 73 73 20 54 6f 6f 6c 62 61 72 } //Quick Access Toolbar  1
		$a_80_7 = {53 6b 69 70 20 41 6c 6c } //Skip All  1
		$a_80_8 = {44 65 63 6c 69 6e 65 } //Decline  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=8
 
}