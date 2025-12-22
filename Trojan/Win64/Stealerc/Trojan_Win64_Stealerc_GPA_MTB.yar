
rule Trojan_Win64_Stealerc_GPA_MTB{
	meta:
		description = "Trojan:Win64/Stealerc.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 65 72 6e 69 6d 61 74 65 } //4 ternimate
		$a_01_1 = {73 65 61 6c 5f 70 6b 00 6b 78 5f 70 6b 00 00 00 73 69 67 6e 5f 70 6b 00 70 72 69 76 69 6c 65 64 67 65 5f 65 73 63 61 6c 61 74 69 6f 6e 00 00 00 61 75 72 6f 74 75 6e } //4
		$a_81_2 = {58 43 68 61 43 68 61 32 30 2d 50 6f 6c 79 31 33 30 35 } //1 XChaCha20-Poly1305
		$a_81_3 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 } //1 expand 32-byte
	condition:
		((#a_81_0  & 1)*4+(#a_01_1  & 1)*4+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}
rule Trojan_Win64_Stealerc_GPA_MTB_2{
	meta:
		description = "Trojan:Win64/Stealerc.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 45 42 57 5a 5a 6b 3c 75 43 45 42 59 5b 72 53 45 42 5f 58 57 42 5f 59 58 } //1 XEBWZZk<uCEBY[rSEB_XWB_YX
		$a_01_1 = {64 43 58 66 44 53 65 53 42 43 46 75 59 5b 5b 57 58 52 45 65 53 55 42 5f 59 58 3c } //1 dCXfDSeSBCFuY[[WXREeSUB_YX<
		$a_01_2 = {3c 6d 64 43 58 66 44 53 65 53 42 43 46 75 59 5b 5b 57 58 52 45 65 53 55 42 5f 59 58 6b 3c 64 73 66 7a 77 75 73 69 75 79 7b 7b 77 78 72 69 7a } //1 <mdCXfDSeSBCFuY[[WXREeSUB_YXk<dsfzwusiuy{{wxriz
		$a_01_3 = {78 73 3c 42 57 45 5d 5d 5f 5a 5a } //1 xs<BWE]]_ZZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}