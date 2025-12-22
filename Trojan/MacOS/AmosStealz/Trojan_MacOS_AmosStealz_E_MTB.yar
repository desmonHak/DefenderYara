
rule Trojan_MacOS_AmosStealz_E_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealz.E!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 do shell script
		$a_00_1 = {65 00 63 00 68 00 6f 00 20 00 24 00 28 00 28 00 52 00 41 00 4e 00 44 00 4f 00 4d 00 20 00 25 00 } //1 echo $((RANDOM %
		$a_00_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 72 00 } //1 system_profiler
		$a_00_3 = {77 00 72 00 69 00 74 00 65 00 54 00 65 00 78 00 74 00 } //1 writeText
		$a_00_4 = {73 00 79 00 73 00 74 00 65 00 6d 00 20 00 61 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 } //1 system attribute
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}