
rule _#PUA_Block_MiniPopups{
	meta:
		description = "!#PUA:Block:MiniPopups,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 33 36 30 53 61 66 65 5c 4c 69 76 65 75 70 } //Software\360Safe\Liveup  1
		$a_80_1 = {43 68 65 6e 67 64 75 20 51 69 6c 75 20 54 65 63 68 6e 6f 6c 6f 67 79 } //Chengdu Qilu Technology  1
		$a_80_2 = {64 6f 77 6e 6c 6f 61 64 65 72 2e 70 64 62 } //downloader.pdb  1
		$a_80_3 = {73 6f 66 74 6d 67 72 2e 6c 75 64 61 73 68 69 2e 63 6f 6d } //softmgr.ludashi.com  1
		$a_80_4 = {73 75 70 70 6f 72 74 2e 65 78 65 } //support.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_MiniPopups_2{
	meta:
		description = "!#PUA:Block:MiniPopups,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_80_0 = {6d 69 6e 69 6e 65 77 73 2e 65 78 65 } //mininews.exe  1
		$a_80_1 = {4d 49 4e 49 50 41 47 45 5f 45 58 45 } //MINIPAGE_EXE  1
		$a_80_2 = {4d 49 4e 49 50 41 47 45 3d 50 6f 70 75 70 } //MINIPAGE=Popup  1
		$a_80_3 = {78 73 66 61 79 61 2e 63 6f 6d } //xsfaya.com  1
		$a_80_4 = {50 4f 50 55 50 5f 44 49 53 50 41 54 43 48 5f 52 45 50 4f 52 54 } //POPUP_DISPATCH_REPORT  1
		$a_80_5 = {53 6f 66 74 4d 61 6e 61 67 65 2e 65 78 65 } //SoftManage.exe  1
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=6
 
}
rule _#PUA_Block_MiniPopups_3{
	meta:
		description = "!#PUA:Block:MiniPopups,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {41 50 50 5f 4d 49 4e 49 54 52 41 59 5f 45 58 45 } //APP_MINITRAY_EXE  1
		$a_80_1 = {4d 49 4e 49 50 41 47 45 3d 50 6f 70 75 70 } //MINIPAGE=Popup  1
		$a_80_2 = {43 4d 59 57 4e 44 5f 4d 49 4e 49 50 41 47 45 } //CMYWND_MINIPAGE  1
		$a_80_3 = {4d 69 6e 69 50 61 67 65 } //MiniPage  1
		$a_80_4 = {78 73 66 61 79 61 2e 63 6f 6d } //xsfaya.com  1
		$a_80_5 = {79 77 77 4c 58 59 34 45 7a 30 70 6d 43 51 37 6b } //ywwLXY4Ez0pmCQ7k  1
		$a_80_6 = {4d 69 6c 6c 69 63 65 6e 74 2e 65 78 65 } //Millicent.exe  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=7
 
}
rule _#PUA_Block_MiniPopups_4{
	meta:
		description = "!#PUA:Block:MiniPopups,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 70 6f 70 5f 70 6f 70 65 78 5c 72 75 6e 64 6c 6c 5c 52 65 6c 65 61 73 65 5c } //1 \pop_popex\rundll\Release\
		$a_01_1 = {58 73 6a 75 66 51 73 70 64 66 74 74 4e 66 6e 70 73 7a } //1 XsjufQspdfttNfnpsz
		$a_01_2 = {52 00 75 00 6e 00 45 00 78 00 74 00 65 00 6e 00 74 00 69 00 6f 00 6e 00 2e 00 74 00 70 00 69 00 } //1 RunExtention.tpi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_MiniPopups_5{
	meta:
		description = "!#PUA:Block:MiniPopups,SIGNATURE_TYPE_PEHSTR,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 53 00 77 00 69 00 74 00 63 00 68 00 57 00 6e 00 64 00 3a 00 20 00 67 00 65 00 74 00 20 00 6d 00 69 00 6e 00 69 00 5f 00 6e 00 65 00 77 00 73 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 2e 00 } //2 AdSwitchWnd: get mini_news failed.
		$a_01_1 = {58 73 6a 75 66 51 73 70 64 66 74 74 4e 66 6e 70 } //2 XsjufQspdfttNfnp
		$a_01_2 = {53 00 74 00 61 00 74 00 69 00 63 00 20 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 20 00 41 00 44 00 3a 00 20 00 61 00 64 00 5f 00 72 00 65 00 73 00 71 00 75 00 65 00 73 00 74 00 5f 00 6e 00 75 00 6d 00 20 00 69 00 73 00 20 00 67 00 72 00 65 00 61 00 74 00 65 00 72 00 20 00 74 00 68 00 61 00 6e 00 } //1 Static wallpaper AD: ad_resquest_num is greater than
		$a_01_3 = {49 00 44 00 5f 00 54 00 49 00 4d 00 45 00 52 00 5f 00 50 00 4f 00 50 00 5f 00 32 00 34 00 5f 00 43 00 4c 00 4f 00 43 00 4b 00 } //1 ID_TIMER_POP_24_CLOCK
		$a_01_4 = {53 00 74 00 61 00 74 00 69 00 63 00 57 00 50 00 41 00 64 00 3a 00 20 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 64 00 65 00 6c 00 61 00 79 00 65 00 64 00 20 00 25 00 64 00 20 00 73 00 65 00 63 00 6f 00 6e 00 64 00 73 00 } //1 StaticWPAd: Request config will be delayed %d seconds
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}
rule _#PUA_Block_MiniPopups_6{
	meta:
		description = "!#PUA:Block:MiniPopups,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 73 00 74 00 65 00 72 00 50 00 64 00 66 00 4d 00 69 00 6e 00 69 00 4e 00 65 00 77 00 73 00 4d 00 61 00 69 00 6e 00 57 00 6e 00 64 00 } //1 MasterPdfMiniNewsMainWnd
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 51 00 69 00 4c 00 75 00 20 00 49 00 6e 00 63 00 2e 00 5c 00 6d 00 69 00 6e 00 69 00 6e 00 65 00 77 00 73 00 5c 00 6c 00 64 00 73 00 } //1 SOFTWARE\QiLu Inc.\mininews\lds
		$a_01_2 = {51 00 33 00 36 00 30 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 7a 00 4d 00 69 00 6e 00 69 00 4e 00 65 00 77 00 73 00 4d 00 75 00 74 00 65 00 78 00 74 00 4e 00 61 00 6d 00 65 00 4c 00 64 00 73 00 } //1 Q360ComputerzMiniNewsMutextNameLds
		$a_01_3 = {6d 00 65 00 64 00 69 00 61 00 2e 00 6c 00 75 00 64 00 61 00 73 00 68 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 6e 00 2f 00 6d 00 69 00 6e 00 69 00 3f 00 70 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 70 00 70 00 76 00 65 00 72 00 3d 00 25 00 73 00 26 00 6d 00 6f 00 64 00 76 00 65 00 72 00 3d 00 25 00 73 00 } //1 media.ludashi.com/n/mini?pid=%s&appver=%s&modver=%s
		$a_01_4 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 6c 00 75 00 64 00 61 00 73 00 68 00 69 00 5c 00 4c 00 6f 00 67 00 5c 00 6c 00 75 00 64 00 61 00 73 00 68 00 69 00 5f 00 4d 00 69 00 6e 00 69 00 6e 00 65 00 77 00 73 00 2e 00 6c 00 6f 00 67 00 } //1 Application Data\ludashi\Log\ludashi_Mininews.log
		$a_01_5 = {5b 68 69 6e 74 65 72 20 6d 69 6e 69 6e 65 77 73 20 71 75 69 74 5d 20 63 68 65 63 6b 20 6f 74 68 65 72 20 6d 69 6e 69 6e 65 77 73 20 70 72 6f 63 65 73 73 21 } //1 [hinter mininews quit] check other mininews process!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}