
rule Trojan_BAT_Heracles_AMTB{
	meta:
		description = "Trojan:BAT/Heracles!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 61 6e 68 53 61 63 68 4c 6f 61 69 58 65 2e 74 78 74 } //DanhSachLoaiXe.txt  1
		$a_80_1 = {44 61 6e 68 53 61 63 68 58 65 2e 74 78 74 } //DanhSachXe.txt  1
		$a_80_2 = {44 61 6e 68 53 61 63 68 43 68 75 79 65 6e 44 69 2e 74 78 74 } //DanhSachChuyenDi.txt  1
		$a_80_3 = {42 61 6f 43 61 6f 2e 74 78 74 } //BaoCao.txt  1
		$a_80_4 = {54 48 44 41 5f 47 72 6f 75 70 31 5f 44 31 33 48 54 30 31 } //THDA_Group1_D13HT01  1
		$a_80_5 = {54 48 44 41 5f 47 72 6f 75 70 31 5f 44 31 33 48 54 30 31 2e 50 72 6f 70 65 72 74 69 65 73 } //THDA_Group1_D13HT01.Properties  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}