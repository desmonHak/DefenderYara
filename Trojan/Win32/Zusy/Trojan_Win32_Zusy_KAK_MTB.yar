
rule Trojan_Win32_Zusy_KAK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 be 6c c6 45 bf 6f c6 45 c0 63 c6 45 c1 61 c6 45 c2 6c c6 45 c3 65 c6 45 c4 40 c6 45 c5 73 c6 45 c6 74 c6 45 c7 64 } //20
		$a_01_1 = {43 3a 5c 43 6e 64 6f 6d 36 2e 73 79 73 } //10 C:\Cndom6.sys
		$a_01_2 = {43 3a 5c 58 69 61 6f 48 2e 73 79 73 } //5 C:\XiaoH.sys
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}