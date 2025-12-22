
rule _#PUA_Block_VrBrothers{
	meta:
		description = "!#PUA:Block:VrBrothers,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 79 4d 61 63 72 6f 5c 52 75 6e 6e 65 72 2e 65 78 65 } //1 MyMacro\Runner.exe
		$a_01_1 = {75 70 64 61 74 65 6d 61 63 72 6f 2e 65 78 65 } //1 updatemacro.exe
		$a_01_2 = {76 72 62 72 6f 74 68 65 72 73 2e 61 64 } //1 vrbrothers.ad
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_VrBrothers_2{
	meta:
		description = "!#PUA:Block:VrBrothers,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 6f 66 74 2e 61 6e 6a 69 61 6e 2e 63 6f 6d } //soft.anjian.com  2
		$a_80_1 = {41 6e 4a 69 61 6e 42 69 6e 64 69 6e 67 49 6e 73 74 61 6c 6c 50 43 2e 68 74 6d 6c } //AnJianBindingInstallPC.html  1
		$a_80_2 = {75 73 65 72 76 61 72 2e 69 6e 69 } //uservar.ini  1
		$a_80_3 = {62 69 6e 64 69 6e 67 2e 65 78 65 } //binding.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_VrBrothers_3{
	meta:
		description = "!#PUA:Block:VrBrothers,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {6d 6d 63 6f 75 6e 74 2e 61 73 70 78 } //mmcount.aspx  1
		$a_80_1 = {43 72 65 61 74 65 50 6f 70 75 70 4d 65 6e 75 } //CreatePopupMenu  1
		$a_80_2 = {76 72 62 72 6f 74 68 65 72 73 } //vrbrothers  1
		$a_80_3 = {62 72 6f 5f 61 64 73 } //bro_ads  1
		$a_80_4 = {7a 79 2e 61 6e 6a 69 61 6e 2e 63 6f 6d } //zy.anjian.com  1
		$a_80_5 = {53 6f 66 74 77 61 72 65 5c 42 72 6f 74 68 65 72 73 5c 53 65 72 76 65 72 } //Software\Brothers\Server  1
		$a_80_6 = {61 64 2e 76 72 62 72 6f 74 68 65 72 73 2e 63 6f 6d 2f 71 6d 61 63 72 6f 2f 76 39 2f 61 64 2d 6d 79 6d 61 63 72 6f 2e 78 6d 6c } //ad.vrbrothers.com/qmacro/v9/ad-mymacro.xml  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule _#PUA_Block_VrBrothers_4{
	meta:
		description = "!#PUA:Block:VrBrothers,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {62 72 6f 5f 61 64 73 } //1 bro_ads
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 75 72 6c } //1 downloadurl
		$a_00_2 = {61 64 2e 76 72 62 72 6f 74 68 65 72 73 2e 63 6f 6d } //1 ad.vrbrothers.com
		$a_00_3 = {64 6f 77 6e 2e 76 72 62 72 6f 74 68 65 72 73 2e 63 6f 6d } //1 down.vrbrothers.com
		$a_00_4 = {61 64 2d 6d 79 6d 61 63 72 6f 2e 78 6d 6c } //1 ad-mymacro.xml
		$a_00_5 = {2f 76 72 62 2f 63 68 6b 6f 6c 76 31 30 2e 61 73 70 78 } //1 /vrb/chkolv10.aspx
		$a_00_6 = {68 69 2e 76 72 62 72 6f 74 68 65 72 73 2e 63 6f 6d 2f 78 6a 6c 2f 6d 6d 63 6f 75 6e 74 2e 61 73 70 78 } //1 hi.vrbrothers.com/xjl/mmcount.aspx
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=7
 
}
rule _#PUA_Block_VrBrothers_5{
	meta:
		description = "!#PUA:Block:VrBrothers,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_80_0 = {73 6f 66 74 2e 61 6e 6a 69 61 6e 2e 63 6f 6d 2f 49 6e 74 65 72 66 61 63 65 2f 42 69 6e 64 69 6e 67 50 43 2f 42 69 6e 64 69 6e 67 55 73 69 6e 67 2e 61 73 70 78 } //soft.anjian.com/Interface/BindingPC/BindingUsing.aspx  2
		$a_80_1 = {73 6f 66 74 2e 61 6e 6a 69 61 6e 2e 63 6f 6d 2f 49 6e 63 6c 75 64 65 2f 42 75 69 6c 64 50 61 67 65 2f 45 78 69 74 41 64 58 4a 4c 2e 73 68 74 6d 6c } //soft.anjian.com/Include/BuildPage/ExitAdXJL.shtml  2
		$a_80_2 = {64 6f 77 6e 2e 76 72 62 72 6f 74 68 65 72 73 2e 63 6f 6d } //down.vrbrothers.com  1
		$a_80_3 = {61 64 2e 76 72 62 72 6f 74 68 65 72 73 2e 63 6f 6d } //ad.vrbrothers.com  1
		$a_80_4 = {68 68 63 74 72 6c 2e 6f 63 78 } //hhctrl.ocx  1
		$a_80_5 = {62 72 6f 5f 61 64 73 } //bro_ads  1
		$a_80_6 = {41 64 64 6f 6e 5f 73 6f 66 74 5f 61 6e 6a 69 61 6e 5f 66 6f 31 72 5f 61 64 64 4f 4e 49 6e 66 6f } //Addon_soft_anjian_fo1r_addONInfo  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=6
 
}