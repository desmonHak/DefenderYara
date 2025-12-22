
rule _#PUA_Block_DriverPack{
	meta:
		description = "!#PUA:Block:DriverPack,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 1a a5 a9 84 b2 e6 d3 1a 21 94 96 37 3d c9 d3 9d 9f 2e 02 7d c0 f8 86 52 5a 14 fd f5 1e cd d7 6f 17 d2 13 b8 39 56 4b 91 b9 a8 a4 fb 59 58 dd 5a 52 25 c3 33 f2 a2 88 57 12 e4 c1 43 cc 5e d9 b6 72 bb 26 f1 c4 20 05 16 a6 04 5b 3f bc 6d 78 42 ca 0d 8d 96 87 6f e9 6a 9b 8a 15 7e 21 c9 33 e0 45 62 0c 71 58 fd 17 8b 61 93 45 81 b9 8f 24 8f c6 49 b7 61 a4 76 22 9f 0b 5b 9e 17 49 15 8b 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#PUA_Block_DriverPack_2{
	meta:
		description = "!#PUA:Block:DriverPack,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 63 4a aa 73 8d 54 b8 de 0f cd 56 f7 99 be 8b 63 a4 cb 72 f2 1f bf 62 23 24 39 56 e1 f2 b3 25 cb 66 3a e8 c0 c9 37 ed df 90 b9 0e 28 c3 2d 7a 80 78 a5 a1 67 bd cc 3f 21 0b e3 5b f2 94 8a 88 60 56 b3 34 c1 b8 ea 04 88 2a b2 dc 05 d0 74 7a fd 2e 8d 85 aa 36 8a d1 8f 66 d6 7b b1 07 5f 8e dc 66 28 07 c7 c4 0a e0 c1 f4 ea 6d e2 9b 6c 40 66 05 3a d3 3c 72 a3 80 a9 82 a5 49 06 e4 53 cf 4f 2f f0 21 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#PUA_Block_DriverPack_3{
	meta:
		description = "!#PUA:Block:DriverPack,SIGNATURE_TYPE_PEHSTR,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 64 72 70 2e 73 75 2f } //1 https://drp.su/
		$a_01_1 = {48 4b 43 55 5c 5c 53 4f 46 54 57 41 52 45 5c 5c 64 72 70 73 75 } //1 HKCU\\SOFTWARE\\drpsu
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 2e 64 72 70 2e 73 75 2f 61 73 73 69 73 74 61 6e 74 2f } //1 download.drp.su/assistant/
		$a_01_3 = {5c 5c 44 52 50 53 75 5c 5c 64 69 61 67 6e 6f 73 74 69 63 73 5c 5c 64 72 69 76 65 72 73 2e 6a 73 6f 6e } //1 \\DRPSu\\diagnostics\\drivers.json
		$a_01_4 = {62 00 69 00 6e 00 2f 00 74 00 6f 00 6f 00 6c 00 73 00 2f 00 44 00 72 00 69 00 76 00 65 00 72 00 50 00 61 00 63 00 6b 00 2d 00 4e 00 6f 00 74 00 69 00 66 00 69 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 bin/tools/DriverPack-Notifier.exe
		$a_01_5 = {62 00 69 00 6e 00 2f 00 74 00 6f 00 6f 00 6c 00 73 00 2f 00 64 00 72 00 69 00 76 00 65 00 72 00 70 00 61 00 63 00 6b 00 2d 00 77 00 67 00 65 00 74 00 2e 00 65 00 78 00 65 00 } //1 bin/tools/driverpack-wget.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}