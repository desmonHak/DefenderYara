
rule Trojan_Win64_Amadey_ADM_MTB{
	meta:
		description = "Trojan:Win64/Amadey.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 00 61 00 62 00 61 00 6e 00 61 00 6b 00 2e 00 72 00 75 00 2f 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //5 xabanak.ru/build.exe
		$a_01_1 = {54 00 45 00 4d 00 50 00 5c 00 61 00 75 00 2e 00 74 00 78 00 74 00 } //3 TEMP\au.txt
		$a_01_2 = {46 00 69 00 6c 00 65 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //2 File Download
		$a_01_3 = {72 00 75 00 6e 00 61 00 73 00 } //1 runas
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=11
 
}