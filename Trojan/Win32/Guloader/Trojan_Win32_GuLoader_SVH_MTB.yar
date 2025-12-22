
rule Trojan_Win32_GuLoader_SVH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 61 72 62 6f 62 20 69 6e 64 72 6d 6d 65 6c 73 65 72 73 } //1 earbob indrmmelsers
		$a_81_1 = {73 74 75 65 68 75 73 65 74 73 2e 65 78 65 } //1 stuehusets.exe
		$a_81_2 = {66 61 72 65 73 69 67 6e 61 6c 65 72 73 } //1 faresignalers
		$a_81_3 = {70 72 6f 62 6f 72 72 6f 77 69 6e 67 20 6d 6f 73 6b 69 71 65 6e } //1 proborrowing moskiqen
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}