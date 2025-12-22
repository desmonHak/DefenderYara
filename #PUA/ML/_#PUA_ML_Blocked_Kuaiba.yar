
rule _#PUA_ML_Blocked_Kuaiba{
	meta:
		description = "!#PUA:ML:Blocked:Kuaiba,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {6b 75 61 69 38 62 6f 78 2e 63 6f 6d } //kuai8box.com  1
		$a_80_1 = {4d 69 6e 69 50 61 67 65 41 64 } //MiniPageAd  1
		$a_80_2 = {4b 75 61 69 38 2d 4d 69 6e 69 50 61 67 65 } //Kuai8-MiniPage  1
		$a_80_3 = {47 4d 4d 69 6e 69 54 69 70 57 65 62 } //GMMiniTipWeb  1
		$a_80_4 = {4b 75 61 69 62 61 4e 65 77 73 4c 61 73 74 44 61 79 } //KuaibaNewsLastDay  1
		$a_80_5 = {4b 75 61 69 62 61 4e 65 77 73 43 6f 75 6e 74 } //KuaibaNewsCount  1
		$a_80_6 = {4b 38 4d 69 6e 69 50 61 67 65 2e 70 64 62 } //K8MiniPage.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}
rule _#PUA_ML_Blocked_Kuaiba_2{
	meta:
		description = "!#PUA:ML:Blocked:Kuaiba,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 00 73 00 73 00 2e 00 6a 00 69 00 70 00 69 00 6e 00 66 00 65 00 69 00 63 00 68 00 65 00 2e 00 63 00 6e 00 } //1 css.jipinfeiche.cn
		$a_01_1 = {63 00 73 00 73 00 2e 00 73 00 75 00 7a 00 68 00 6f 00 75 00 6c 00 65 00 69 00 7a 00 68 00 65 00 6e 00 2e 00 63 00 6f 00 6d 00 } //1 css.suzhouleizhen.com
		$a_01_2 = {61 00 64 00 76 00 65 00 72 00 74 00 63 00 68 00 65 00 63 00 6b 00 } //1 advertcheck
		$a_01_3 = {54 00 65 00 6e 00 63 00 65 00 6e 00 74 00 5c 00 54 00 65 00 6e 00 63 00 65 00 6e 00 74 00 54 00 72 00 61 00 76 00 65 00 6c 00 65 00 72 00 5c 00 31 00 30 00 30 00 5c 00 54 00 74 00 43 00 6f 00 6e 00 66 00 2e 00 64 00 61 00 74 00 } //1 Tencent\TencentTraveler\100\TtConf.dat
		$a_01_4 = {47 4d 47 61 6d 65 53 74 61 72 74 5c 62 69 6e 5c 72 65 6c 65 61 73 65 5f 73 74 61 74 69 63 5c 47 4d 55 6e 50 61 63 6b 65 72 2e 70 64 62 } //1 GMGameStart\bin\release_static\GMUnPacker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}