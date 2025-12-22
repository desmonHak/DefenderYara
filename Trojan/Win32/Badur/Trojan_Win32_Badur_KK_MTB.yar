
rule Trojan_Win32_Badur_KK_MTB{
	meta:
		description = "Trojan:Win32/Badur.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {6d 61 69 6e 2e 28 2a [0-0f] 29 2e 53 65 74 44 79 6e 61 6d 69 63 43 72 65 64 65 6e 74 69 61 6c 73 } //10
		$a_03_1 = {6d 61 69 6e 2e 28 2a [0-0f] 29 2e 53 65 74 53 63 6b 73 35 53 72 76 } //15
		$a_03_2 = {6d 61 69 6e 2e 28 2a [0-0f] 29 2e 42 34 63 6b 43 78 6e 6e 65 63 74 } //20
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*15+(#a_03_2  & 1)*20) >=35
 
}