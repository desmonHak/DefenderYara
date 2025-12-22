
rule Trojan_Win64_ValleyRAT_TBK_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.TBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 65 68 62 65 32 35 33 } //1 yehbe253
		$a_01_1 = {5c 54 65 6c 65 67 72 61 6d 2e 6c 6e 6b } //1 \Telegram.lnk
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 65 73 6b 74 6f 70 5c 51 51 2e 6c 6e 6b } //1 C:\Users\Public\Desktop\QQ.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}