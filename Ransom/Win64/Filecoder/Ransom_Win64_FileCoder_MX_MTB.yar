
rule Ransom_Win64_Filecoder_MX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 cc a7 11 00 31 c9 31 ff 48 89 fe 0f 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_Filecoder_MX_MTB_2{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 48 8b 5c 24 18 e8 27 ff ff ff e9 49 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_Filecoder_MX_MTB_3{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_01_1 = {78 6f 72 5f 6c 6f 63 6b 65 72 } //1 xor_locker
		$a_01_2 = {64 65 63 72 79 70 74 } //1 decrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Ransom_Win64_Filecoder_MX_MTB_4{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 8d d0 03 00 00 4c 8b 85 f8 04 00 00 48 8d 55 c0 48 8d 45 c0 c7 44 24 28 01 00 00 00 48 8d 4d b0 48 89 4c 24 20 48 89 c1 e8 72 13 00 00 48 8b 8d 00 05 00 00 48 8b 95 f8 04 00 00 48 8d 45 c0 49 89 c9 49 89 d0 ba } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_Filecoder_MX_MTB_5{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_01_2 = {74 6f 20 72 65 73 74 6f 72 65 20 74 68 65 6d } //1 to restore them
		$a_01_3 = {6d 65 73 73 61 67 65 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 } //1 message will be deleted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Ransom_Win64_Filecoder_MX_MTB_6{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 42 79 74 65 2d 52 61 6e 73 6f 6d 77 61 72 65 } //1 EByte-Ransomware
		$a_01_1 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_01_2 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
		$a_01_3 = {73 65 6e 64 4c 6f 63 6b 65 72 49 44 } //1 sendLockerID
		$a_01_4 = {73 65 74 57 61 6c 6c 70 61 70 65 72 } //1 setWallpaper
		$a_01_5 = {67 65 74 44 72 69 76 65 73 } //1 getDrives
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}