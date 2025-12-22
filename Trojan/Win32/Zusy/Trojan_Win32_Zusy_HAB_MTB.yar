
rule Trojan_Win32_Zusy_HAB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 61 75 74 6f 2e 41 75 74 6f 4d 6f 64 65 43 68 72 6f 6d 65 47 61 74 68 65 72 } //1 /auto.AutoModeChromeGather
		$a_01_1 = {25 73 2e 74 61 72 2e 67 7a } //1 %s.tar.gz
		$a_01_2 = {62 69 74 73 2d 70 72 6f 6a 65 63 74 2f 62 69 74 73 2f 75 74 69 6c } //1 bits-project/bits/util
		$a_03_3 = {67 61 74 68 65 72 2e 74 48 89 ?? 48 ?? 72 2e 74 61 72 2e 67 7a 48 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*10) >=13
 
}