
rule TrojanDownloader_Win32_Sock5Systemz_MK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Sock5Systemz.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 14 38 8b ca 8d 41 01 89 45 f0 8a 01 41 84 c0 } //15
		$a_01_1 = {8b 5c 24 38 84 c0 59 6a 01 0f b6 db 58 0f 45 d8 } //10
		$a_01_2 = {67 70 74 3d 25 2e 38 78 26 69 6e 63 3d 25 64 26 61 64 76 69 7a 6f 72 3d 25 64 26 62 6f 78 3d 25 64 26 68 70 3d 25 78 26 6c 70 3d 25 78 26 6c 69 6e 65 3d 25 64 26 6f 73 3d 25 64 2e 25 64 2e 25 30 34 64 26 66 6c 61 67 3d 25 64 26 69 74 64 3d 25 64 } //3 gpt=%.8x&inc=%d&advizor=%d&box=%d&hp=%x&lp=%x&line=%d&os=%d.%d.%04d&flag=%d&itd=%d
		$a_01_3 = {2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //2 .\PhysicalDrive0
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=30
 
}