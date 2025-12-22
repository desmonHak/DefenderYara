
rule Trojan_Win32_DarkComet_ADT_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b fe 33 d2 8b 4d 0c 85 c9 75 04 c9 c2 ?? ?? 83 fa 10 75 02 33 d2 ac 32 82 ?? ?? ?? ?? aa 42 49 75 } //3
		$a_01_1 = {57 8b 4d 0c 8b 7d 08 51 0f 31 33 c1 83 e0 0f 04 41 aa 59 49 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}