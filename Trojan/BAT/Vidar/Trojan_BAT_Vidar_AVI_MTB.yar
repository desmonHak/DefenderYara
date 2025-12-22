
rule Trojan_BAT_Vidar_AVI_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 25 06 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 25 16 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 0b 07 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Vidar_AVI_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 20 70 65 72 73 69 73 74 65 6e 74 20 73 63 68 65 64 75 6c 65 64 20 74 61 73 6b } //1 Create persistent scheduled task
		$a_01_1 = {4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 41 63 74 69 6f 6e 20 2d 45 78 65 63 75 74 65 20 24 74 65 6d 70 50 61 74 68 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //2 New-ScheduledTaskAction -Execute $tempPath -ErrorAction SilentlyContinue
		$a_01_2 = {4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 54 72 69 67 67 65 72 20 2d 41 74 4c 6f 67 4f 6e 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //3 New-ScheduledTaskTrigger -AtLogOn -ErrorAction SilentlyContinue
		$a_01_3 = {4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 53 65 74 74 69 6e 67 73 53 65 74 20 2d 48 69 64 64 65 6e 20 2d 41 6c 6c 6f 77 53 74 61 72 74 49 66 4f 6e 42 61 74 74 65 72 69 65 73 20 2d 44 6f 6e 74 53 74 6f 70 49 66 47 6f 69 6e 67 4f 6e 42 61 74 74 65 72 69 65 73 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //4 New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ErrorAction SilentlyContinue
		$a_01_4 = {4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 50 72 69 6e 63 69 70 61 6c 20 2d 55 73 65 72 49 64 20 24 65 6e 76 3a 55 53 45 52 4e 41 4d 45 20 2d 4c 6f 67 6f 6e 54 79 70 65 20 53 34 55 20 2d 52 75 6e 4c 65 76 65 6c 20 48 69 67 68 65 73 74 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //5 New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest -ErrorAction SilentlyContinue
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5) >=15
 
}