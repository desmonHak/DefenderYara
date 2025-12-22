
rule _#PUA_Block_BitComet{
	meta:
		description = "!#PUA:Block:BitComet,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 00 69 00 74 00 63 00 6f 00 6d 00 65 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 6e 00 2f 00 70 00 72 00 69 00 76 00 61 00 63 00 79 00 2d 00 70 00 6f 00 6c 00 69 00 63 00 79 00 } //1 bitcomet.com/en/privacy-policy
		$a_01_1 = {2f 00 74 00 6d 00 70 00 2f 00 62 00 69 00 74 00 63 00 6f 00 6d 00 65 00 74 00 2d 00 69 00 70 00 63 00 2d 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 /tmp/bitcomet-ipc-connection
		$a_01_2 = {42 00 69 00 74 00 43 00 6f 00 6d 00 65 00 74 00 2e 00 65 00 78 00 65 00 } //1 BitComet.exe
		$a_01_3 = {49 00 44 00 52 00 5f 00 44 00 4c 00 4c 00 5f 00 42 00 49 00 54 00 43 00 4f 00 4d 00 45 00 54 00 5f 00 52 00 45 00 53 00 } //1 IDR_DLL_BITCOMET_RES
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}