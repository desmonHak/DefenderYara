
rule Trojan_Win32_Guloader_KQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 41 6c 64 65 68 79 64 61 73 65 5c 75 6e 65 6e 63 6f 75 72 61 67 69 6e 67 2e 69 6e 69 } //1 \Aldehydase\unencouraging.ini
		$a_81_1 = {74 65 72 6d 69 6e 73 72 65 6e 74 65 72 73 5c 74 65 74 72 61 68 79 64 72 69 63 5c 74 65 61 6b 74 72 65 72 6e 65 73 } //1 terminsrenters\tetrahydric\teaktrernes
		$a_81_2 = {73 75 6b 6b 65 72 73 6b 61 61 6c 65 6e 73 2e 7a 69 70 } //1 sukkerskaalens.zip
		$a_81_3 = {64 61 6e 73 6b 74 6f 70 5c 6f 70 73 70 61 72 69 6e 67 73 6b 6f 6e 74 69 65 6e 65 2e 62 69 6e } //1 dansktop\opsparingskontiene.bin
		$a_81_4 = {63 61 6c 65 64 6f 6e 69 61 6e 5c 62 79 67 67 65 73 6b 69 6b 2e 64 6c 6c } //1 caledonian\byggeskik.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}