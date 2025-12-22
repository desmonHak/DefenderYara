
rule Trojan_BAT_Tedy_ARR_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 58 61 d2 9c 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d dd } //15
		$a_01_1 = {4b 00 6a 00 51 00 72 00 4f 00 43 00 77 00 73 00 43 00 41 00 51 00 4f 00 44 00 30 00 6f 00 41 00 48 00 67 00 49 00 3d 00 } //5 KjQrOCwsCAQOD0oAHgI=
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}
rule Trojan_BAT_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 32 31 61 38 35 30 33 34 2d 64 37 32 35 2d 34 31 64 38 2d 39 61 62 39 2d 31 39 35 30 37 66 61 31 65 32 30 63 } //8 $21a85034-d725-41d8-9ab9-19507fa1e20c
		$a_01_1 = {43 6f 6d 70 75 74 65 72 53 63 61 6e 6e 65 72 2e 65 78 65 } //10 ComputerScanner.exe
		$a_01_2 = {3c 73 74 72 65 61 6d 53 74 72 65 61 6d 3e 35 5f 5f 36 } //2 <streamStream>5__6
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2) >=20
 
}