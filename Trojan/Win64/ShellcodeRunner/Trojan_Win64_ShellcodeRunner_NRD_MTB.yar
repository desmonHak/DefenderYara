
rule Trojan_Win64_ShellcodeRunner_NRD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 "
		
	strings :
		$a_81_0 = {62 63 72 79 70 74 70 72 69 6d 69 74 69 76 65 73 2e 64 6c 6c } //1 bcryptprimitives.dll
		$a_81_1 = {63 69 70 68 65 72 2e 4e 65 77 43 42 43 44 65 63 72 79 70 74 65 72 3a 20 49 56 } //1 cipher.NewCBCDecrypter: IV
		$a_81_2 = {6d 61 69 6e 2e 67 65 74 53 68 65 6c 6c 63 6f 64 65 46 72 61 67 6d 65 6e 74 } //2 main.getShellcodeFragment
		$a_81_3 = {6d 61 69 6e 2e 67 65 74 41 6c 6c 53 68 65 6c 6c 63 6f 64 65 46 72 61 67 6d 65 6e 74 73 } //1 main.getAllShellcodeFragments
		$a_81_4 = {6d 61 69 6e 2e 67 65 74 4f 62 66 75 73 63 61 74 65 64 53 68 65 6c 6c 63 6f 64 65 } //1 main.getObfuscatedShellcode
		$a_81_5 = {6d 61 69 6e 2e 64 65 63 6f 64 65 48 65 78 53 74 72 69 6e 67 } //1 main.decodeHexString
		$a_81_6 = {6d 61 69 6e 2e 64 65 6f 62 66 75 73 63 61 74 65 53 68 65 6c 6c 63 6f 64 65 } //1 main.deobfuscateShellcode
		$a_81_7 = {6d 61 69 6e 2e 47 65 74 4e 74 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 main.GetNtProtectVirtualMemory
		$a_81_8 = {6d 61 69 6e 2e 65 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 } //1 main.executeShellcode
		$a_81_9 = {6d 61 69 6e 2e 47 65 74 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 main.GetNtAllocateVirtualMemory
		$a_81_10 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 53 74 72 69 6e 67 } //1 main.decryptString
		$a_81_11 = {65 6e 63 72 79 70 74 42 6c 6f 63 6b 47 65 6e 65 72 69 63 } //1 encryptBlockGeneric
		$a_81_12 = {58 4f 52 4b 65 79 53 74 72 65 61 6d } //1 XORKeyStream
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=14
 
}