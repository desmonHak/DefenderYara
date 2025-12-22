
rule Trojan_Win64_Runner_AHB_MTB{
	meta:
		description = "Trojan:Win64/Runner.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 41 4e 44 4f 4d 5f 43 4f 4d 4d 45 4e 54 5f } //20 RANDOM_COMMENT_
		$a_81_1 = {73 74 61 72 74 20 2f 62 20 4b 4d 53 45 4c 44 49 2e 2e 65 78 65 20 3e 6e 75 6c 20 32 3e 26 31 20 26 20 70 69 6e 67 20 2d 6e 20 31 31 20 31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c 20 32 3e 26 31 20 26 20 75 6e 72 61 72 20 78 20 2d 6f 2b 20 2d 70 64 69 61 6c 6f 67 20 22 64 69 61 6c 6f 67 2e 72 61 72 } //40 start /b KMSELDI..exe >nul 2>&1 & ping -n 11 127.0.0.1 >nul 2>&1 & unrar x -o+ -pdialog "dialog.rar
		$a_03_2 = {66 89 01 48 8d 85 ?? ?? ?? ?? 48 8b f8 33 c0 b9 ?? ?? ?? ?? f3 aa 4c 8d 4d } //10
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*40+(#a_03_2  & 1)*10) >=70
 
}