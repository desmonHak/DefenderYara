
rule TrojanDownloader_Win32_Fusogstome_A_dha{
	meta:
		description = "TrojanDownloader:Win32/Fusogstome.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 64 72 69 76 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f } //1 https://drive.google.com/
		$a_01_1 = {66 75 73 6c 6f 67 76 77 2e 65 78 65 } //1 fuslogvw.exe
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 31 30 31 2e 30 2e 30 2e 30 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 } //1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}