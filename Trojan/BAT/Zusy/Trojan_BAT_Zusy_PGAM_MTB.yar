
rule Trojan_BAT_Zusy_PGAM_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PGAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 13 1f 11 1f 1f 10 64 d1 13 18 11 18 d2 13 2c 11 18 1e 63 d1 13 18 11 17 11 09 91 13 22 11 17 11 09 11 22 11 27 61 ?? ?? ?? 58 61 11 2c 61 d2 9c 11 22 13 21 ?? ?? ?? 58 13 09 11 09 11 2a 32 a4 } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e 65 78 65 } //5 DownloaderApp.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}