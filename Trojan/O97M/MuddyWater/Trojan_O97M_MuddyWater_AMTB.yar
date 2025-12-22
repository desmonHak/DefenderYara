
rule Trojan_O97M_MuddyWater_AMTB{
	meta:
		description = "Trojan:O97M/MuddyWater!AMTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 61 74 68 61 73 73 74 72 69 6e 67 70 61 74 68 3d 22 63 3a 5c 5c 75 73 65 72 73 5c 5c 70 75 62 6c 69 63 5c 5c 68 6f 73 74 6d 61 6e 61 67 65 72 2e 6c 6f 67 } //1 pathasstringpath="c:\\users\\public\\hostmanager.log
		$a_01_1 = {73 75 62 70 6f 6c 28 66 69 6c 65 70 61 74 68 61 73 73 74 72 69 6e 67 29 73 68 65 6c 6c 22 63 6d 64 2e 65 78 65 2f 63 22 22 22 26 66 69 6c 65 70 61 74 68 26 22 22 22 22 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 } //1 subpol(filepathasstring)shell"cmd.exe/c"""&filepath&"""",vbnormalfoc
		$a_01_2 = {66 6f 72 69 3d 30 74 6f 75 62 6f 75 6e 64 28 62 79 74 65 61 72 72 61 79 29 68 65 78 62 79 74 65 3d 6d 69 64 28 68 65 78 73 74 72 69 6e 67 2c 69 2a 32 2b 31 2c 32 29 62 79 74 65 61 72 72 61 79 28 69 29 3d 63 62 79 74 65 28 22 26 68 22 26 68 65 78 62 79 74 65 29 6e 65 78 74 69 } //1 fori=0toubound(bytearray)hexbyte=mid(hexstring,i*2+1,2)bytearray(i)=cbyte("&h"&hexbyte)nexti
		$a_01_3 = {6f 70 65 6e 70 61 74 68 5f 32 66 6f 72 62 69 6e 61 72 79 61 63 63 65 73 73 77 72 69 74 65 61 73 23 66 69 6c 65 6e 75 6d 70 75 74 23 66 69 6c 65 6e 75 6d 2c 2c 62 69 6e 61 72 79 64 61 74 61 63 6c 6f 73 65 23 66 69 6c 65 6e 75 6d } //1 openpath_2forbinaryaccesswriteas#filenumput#filenum,,binarydataclose#filenum
		$a_01_4 = {62 61 73 65 36 34 73 74 72 69 6e 67 3d 75 73 65 72 66 6f 72 6d 31 2e 74 65 78 74 62 6f 78 31 2e 74 65 78 74 } //1 base64string=userform1.textbox1.text
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}