
rule Trojan_Win64_DCRat_MK_MTB{
	meta:
		description = "Trojan:Win64/DCRat.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {f2 48 0f 2a d1 66 0f 6e c8 f3 0f e6 c9 f3 0f e6 c0 f2 0f 58 c0 f2 0f 5c c8 f2 0f 59 ca f2 0f 11 4d b7 } //20
		$a_01_1 = {43 75 72 72 65 33 36 30 6c 65 61 6b 66 69 78 65 72 2e 65 78 65 } //15 Curre360leakfixer.exe
		$a_01_2 = {25 73 5c 6f 6b 5f 25 6c 64 2e 73 74 6d 6c } //3 %s\ok_%ld.stml
		$a_01_3 = {25 73 5c 6f 6b 5f 25 6c 64 2e 74 78 74 } //2 %s\ok_%ld.txt
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=40
 
}