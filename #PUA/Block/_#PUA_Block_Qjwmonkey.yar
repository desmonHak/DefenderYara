
rule _#PUA_Block_Qjwmonkey{
	meta:
		description = "!#PUA:Block:Qjwmonkey,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {77 2e 6e 61 6e 77 65 6e 67 2e 63 6e } //w.nanweng.cn  1
		$a_80_1 = {49 6e 73 44 65 66 74 2e 78 6d 6c } //InsDeft.xml  1
		$a_80_2 = {45 3a 5c 31 32 33 2e 70 64 62 } //E:\123.pdb  1
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=3
 
}
rule _#PUA_Block_Qjwmonkey_2{
	meta:
		description = "!#PUA:Block:Qjwmonkey,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 6a 71 2e 66 73 73 38 2e 63 6e } //sjq.fss8.cn  2
		$a_80_1 = {48 65 20 46 65 69 20 59 75 6e 20 42 69 61 6f 20 58 69 6e 20 58 69 20 4b 65 20 4a 69 20 59 6f 75 20 58 69 61 6e 20 47 6f 6e 67 20 53 69 } //He Fei Yun Biao Xin Xi Ke Ji You Xian Gong Si  1
		$a_80_2 = {2f 61 70 69 2f 74 61 73 6b 2f 72 65 70 6f 72 74 } ///api/task/report  1
		$a_80_3 = {4d 65 6e 75 50 6f 70 75 70 } //MenuPopup  1
		$a_80_4 = {68 74 74 70 5f 70 72 6f 78 79 } //http_proxy  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Qjwmonkey_3{
	meta:
		description = "!#PUA:Block:Qjwmonkey,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {40 31 5f 33 36 30 2e 65 78 65 } //@1_360.exe  1
		$a_80_1 = {32 33 34 35 45 78 70 6c 6f 72 65 72 2e 65 78 65 } //2345Explorer.exe  1
		$a_80_2 = {71 69 61 6e 79 69 6e 67 30 31 30 32 30 33 2e 31 31 65 78 65 } //qianying010203.11exe  1
		$a_00_3 = {64 00 61 00 74 00 61 00 2e 00 67 00 6f 00 6f 00 73 00 61 00 69 00 2e 00 63 00 6f 00 6d 00 } //1 data.goosai.com
		$a_00_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 7a 00 72 00 79 00 39 00 37 00 2e 00 63 00 6f 00 6d 00 2f 00 79 00 6f 00 75 00 78 00 69 00 2f 00 69 00 6e 00 64 00 65 00 78 00 5f 00 } //1 http://cdn.zry97.com/youxi/index_
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Qjwmonkey_4{
	meta:
		description = "!#PUA:Block:Qjwmonkey,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 61 5c 47 6c 6f 62 61 6c 4d 67 72 2e 64 62 } //4 Data\GlobalMgr.db
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 7a 00 72 00 79 00 39 00 37 00 2e 00 63 00 6f 00 6d 00 2f 00 79 00 6f 00 75 00 78 00 69 00 } //2 http://cdn.zry97.com/youxi
		$a_01_2 = {44 00 6f 00 77 00 6e 00 4c 00 6f 00 61 00 64 00 46 00 72 00 61 00 6d 00 65 00 5f 00 73 00 70 00 6c 00 61 00 73 00 68 00 } //1 DownLoadFrame_splash
		$a_01_3 = {7a 00 68 00 75 00 64 00 6f 00 6e 00 67 00 66 00 61 00 6e 00 67 00 79 00 75 00 2e 00 65 00 78 00 65 00 } //1 zhudongfangyu.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}