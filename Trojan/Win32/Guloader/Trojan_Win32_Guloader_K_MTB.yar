
rule Trojan_Win32_Guloader_K_MTB{
	meta:
		description = "Trojan:Win32/Guloader.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 69 63 74 61 63 20 76 69 64 74 6c 66 74 69 67 68 65 64 } //1 tictac vidtlftighed
		$a_81_1 = {6f 70 67 61 6e 67 65 73 } //1 opganges
		$a_81_2 = {6b 65 6e 64 65 72 6d 69 6e 65 72 73 20 66 6c 65 74 63 68 65 72 73 } //1 kenderminers fletchers
		$a_81_3 = {73 6d 65 72 74 65 6e 73 20 70 65 74 74 69 66 6f 67 67 69 6e 67 20 6d 61 69 6c 77 6f 6d 61 6e } //1 smertens pettifogging mailwoman
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}