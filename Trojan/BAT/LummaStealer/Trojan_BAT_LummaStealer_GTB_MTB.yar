
rule Trojan_BAT_LummaStealer_GTB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {13 06 08 20 b7 5c 8a 00 6a 5e 26 16 13 0a 2b 2b 11 05 11 0a 8f 18 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //10
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e 65 78 65 } //DownloaderApp.exe  1
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_3 = {61 63 61 38 35 63 2d 37 31 32 34 2d 34 37 33 64 2d 61 32 65 63 2d 32 36 39 35 66 64 66 30 38 38 38 65 } //1 aca85c-7124-473d-a2ec-2695fdf0888e
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}