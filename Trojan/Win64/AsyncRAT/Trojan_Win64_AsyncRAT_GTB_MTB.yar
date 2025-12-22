
rule Trojan_Win64_AsyncRAT_GTB_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 8b cf 4d 85 c9 74 19 33 d2 48 8b c1 48 f7 f6 42 0f b6 04 02 41 30 04 0a 48 ff c1 49 3b c9 } //10
		$a_01_1 = {4e 8d 04 0f 49 8b c3 49 f7 e1 48 c1 ea 03 48 8d 04 d2 49 8b c9 48 2b c8 42 0f b6 04 21 43 32 04 10 41 88 00 49 ff c1 4c 3b cb } //10
		$a_01_2 = {63 75 72 6c 5f 65 61 73 79 5f 63 6c 65 61 6e 75 70 } //1 curl_easy_cleanup
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}