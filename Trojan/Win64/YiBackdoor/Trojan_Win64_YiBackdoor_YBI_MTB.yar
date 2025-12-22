
rule Trojan_Win64_YiBackdoor_YBI_MTB{
	meta:
		description = "Trojan:Win64/YiBackdoor.YBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f c8 66 0f fd cf 66 0f f9 cb 30 0c 3e 66 0f 6f d8 66 0f 6f cb 66 0f 6d fb } //1
		$a_01_1 = {66 0f 6f c3 66 0f 38 30 d0 66 0f 6d cf 66 0f 6c ca 66 0f 6f c3 66 0f 6f cb 66 0f 62 c2 66 0f 6a ca 66 0f f9 d8 66 0f f9 fd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}