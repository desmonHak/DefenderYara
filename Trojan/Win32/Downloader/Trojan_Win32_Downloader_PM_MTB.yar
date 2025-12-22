
rule Trojan_Win32_Downloader_PM_MTB{
	meta:
		description = "Trojan:Win32/Downloader.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 20 44 6f 77 6e 6c 6f 61 64 65 72 } //1 HTTP Downloader
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 72 32 2e 65 2d 7a 2e 68 6f 73 74 2f 39 64 34 66 66 63 32 61 2d 33 39 37 38 2d 34 65 62 37 2d 39 64 62 39 2d 63 34 62 39 36 63 31 39 31 36 38 32 2f 75 79 38 73 71 66 79 30 2e 65 78 65 } //4 https://r2.e-z.host/9d4ffc2a-3978-4eb7-9db9-c4b96c191682/uy8sqfy0.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}