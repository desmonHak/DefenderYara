
rule _#PUA_ML_Blocked_Youxun{
	meta:
		description = "!#PUA:ML:Blocked:Youxun,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 63 72 65 65 6e 53 61 76 65 72 5c 48 69 64 65 54 69 6d 65 2e 69 6e 69 } //ScreenSaver\HideTime.ini  1
		$a_80_1 = {53 63 72 65 65 6e 53 61 76 65 72 5c 44 54 69 6d 65 2e 64 61 74 } //ScreenSaver\DTime.dat  1
		$a_80_2 = {70 61 70 65 72 61 7a 2e 73 63 72 65 65 6e 2e 64 64 4c 69 76 65 73 2e 63 6f 6d 2f 63 6f 75 6e 74 2e 64 6f } //paperaz.screen.ddLives.com/count.do  1
		$a_80_3 = {73 63 72 65 65 6e 2e 64 64 4c 69 76 65 73 2e 63 6f 6d 2f 73 63 72 65 65 6e 2f 6c 6f 63 6b 2e 69 6e 69 } //screen.ddLives.com/screen/lock.ini  1
		$a_80_4 = {6b 75 77 61 6e 54 65 6d 70 5c 6b 75 77 61 6e 5c 74 72 75 6e 6b 5c 73 72 63 5c 53 63 72 65 65 6e 53 61 76 65 72 5c 52 65 6c 65 61 73 65 5c 53 63 72 65 65 6e 53 61 76 65 72 2e 70 64 62 } //kuwanTemp\kuwan\trunk\src\ScreenSaver\Release\ScreenSaver.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}