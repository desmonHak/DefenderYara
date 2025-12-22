
rule Trojan_Win64_FileCoder_NF_MTB{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c8 ff eb 31 48 8b cb e8 a5 00 00 00 48 85 c0 75 05 83 cf ?? eb 0e 48 89 05 b8 1c 05 00 48 89 05 99 1c 05 00 33 c9 e8 5a 32 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_FileCoder_NF_MTB_2{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 41 3b 11 41 8d 40 01 0f b7 51 02 41 0f 44 c0 48 83 c1 02 49 83 c1 02 44 8b c0 66 83 fa 3d 75 df } //2
		$a_01_1 = {49 8b 0a 45 8b c7 66 83 39 2d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_FileCoder_NF_MTB_3{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 41 01 48 83 f8 ?? 7c dc 31 c0 eb 19 48 89 c1 48 c1 e0 ?? 48 8d 15 43 2b 59 00 48 01 c2 } //5
		$a_01_1 = {5a 5a 58 75 4b 37 54 } //1 ZZXuK7T
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_FileCoder_NF_MTB_4{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 6f 72 69 67 69 6e 61 6c 20 64 65 6c 65 74 65 64 } //2 File encrypted and original deleted
		$a_01_1 = {45 72 72 6f 72 20 65 6e 63 72 79 70 74 69 6e 67 20 66 69 6c 65 } //1 Error encrypting file
		$a_01_2 = {53 65 6e 64 20 58 20 42 69 74 63 6f 69 6e 20 74 6f 20 61 64 64 72 65 73 73 20 59 20 74 6f 20 74 68 65 6f 72 65 74 69 63 61 6c 6c 79 20 64 65 63 72 79 70 74 20 74 68 65 6d } //2 Send X Bitcoin to address Y to theoretically decrypt them
		$a_01_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 74 68 65 6f 72 65 74 69 63 61 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been theoretically encrypted
		$a_01_4 = {53 74 61 72 74 69 6e 67 20 74 68 65 6f 72 65 74 69 63 61 6c 20 65 6e 63 72 79 70 74 69 6f 6e 20 6f 66 20 64 69 72 65 63 74 6f 72 79 3a } //1 Starting theoretical encryption of directory:
		$a_01_5 = {54 48 45 4f 52 45 54 49 43 41 4c 20 52 41 4e 53 4f 4d 20 4e 4f 54 45 } //2 THEORETICAL RANSOM NOTE
		$a_01_6 = {47 65 6e 65 72 61 74 65 64 20 4b 65 79 } //1 Generated Key
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=10
 
}
rule Trojan_Win64_FileCoder_NF_MTB_5{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 57 69 6e 64 6f 77 43 6c 61 73 73 } //2 RansomwareWindowClass
		$a_01_1 = {63 6d 64 20 2f 63 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 6d 73 2d 73 65 74 74 69 6e 67 73 20 2f 66 } //1 cmd /c reg delete HKCU\Software\Classes\ms-settings /f
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_3 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //1 wbadmin delete catalog -quiet
		$a_01_4 = {59 6f 75 72 20 50 43 20 69 73 20 45 6e 63 72 79 70 74 65 64 } //1 Your PC is Encrypted
		$a_01_5 = {6c 6f 6c 2c 20 6d 61 64 64 6f 78 } //1 lol, maddox
		$a_01_6 = {6c 65 74 73 20 73 69 74 20 64 6f 77 6e 20 61 73 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 74 68 65 6e 20 64 65 6c 65 74 65 64 } //1 lets sit down as your files are encrypted and then deleted
		$a_01_7 = {64 6f 6e 27 74 20 74 72 79 20 74 6f 20 72 65 73 65 74 2c 20 79 6f 75 72 20 70 63 20 69 73 20 61 6c 72 65 61 64 79 20 66 75 63 6b 65 64 20 62 79 20 74 68 65 20 74 69 6d 65 20 79 6f 75 20 72 65 61 64 20 74 68 69 73 20 6c 69 6e 65 2e } //1 don't try to reset, your pc is already fucked by the time you read this line.
		$a_01_8 = {66 69 6c 65 20 64 65 63 72 79 70 74 69 6f 6e 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 2e 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 73 20 68 61 76 65 20 61 6c 72 65 61 64 79 20 62 65 65 6e 20 64 65 6c 65 74 65 64 } //1 file decryption is impossible. the decryption keys have already been deleted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=10
 
}
rule Trojan_Win64_FileCoder_NF_MTB_6{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 2e 00 6a 00 70 00 67 00 } //1 Ransom.jpg
		$a_01_1 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //2 vssadmin delete shadows /all /quiet
		$a_01_2 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 keylog.txt
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_4 = {53 00 65 00 74 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 24 00 74 00 72 00 75 00 65 00 } //1 Set-MpPreference -DisableRealtimeMonitoring $true
		$a_01_5 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 } //1 net stop WinDefend
		$a_01_6 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 4f 00 52 00 5f 00 4c 00 4f 00 53 00 45 00 5f 00 45 00 56 00 45 00 52 00 59 00 54 00 48 00 49 00 4e 00 47 00 2e 00 74 00 78 00 74 00 } //2 DECRYPT_OR_LOSE_EVERYTHING.txt
		$a_01_7 = {59 00 4f 00 55 00 52 00 20 00 53 00 59 00 53 00 54 00 45 00 4d 00 20 00 49 00 53 00 20 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 } //1 YOUR SYSTEM IS LOCKED
		$a_01_8 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 } //2 RansomWindow
		$a_01_9 = {77 00 6d 00 69 00 63 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 wmic shadowcopy call create
		$a_01_10 = {73 00 63 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 77 00 75 00 61 00 75 00 73 00 65 00 72 00 76 00 20 00 73 00 74 00 61 00 72 00 74 00 3d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 } //1 sc config wuauserv start=disabled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=14
 
}