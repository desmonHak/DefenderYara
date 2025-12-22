
rule _#ALF_Trojan_Linux_SamDust{
	meta:
		description = "!#ALF:Trojan:Linux/SamDust.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 0c 00 00 "
		
	strings :
		$a_01_0 = {4d 41 44 21 } //4 MAD!
		$a_01_1 = {50 40 69 7d 42 7e 37 30 6c 48 5a 5b 7a 2b 63 20 43 79 5f 6a 4b 44 46 45 4a 7b 3f 75 5d 33 23 3c 73 3b 6f 2f 6b 47 54 3a 3e 70 2c 38 55 68 57 2e 51 77 5e 58 5c 49 65 67 4d 59 29 4c 61 31 36 74 3d 71 35 4f 60 24 39 7c 2a 26 34 4e 78 2d 64 32 22 56 62 66 72 76 27 25 28 6e 41 53 6d 52 21 } //4 P@i}B~70lHZ[z+c Cy_jKDFEJ{?u]3#<s;o/kGT:>p,8UhW.Qw^X\IegMY)La16t=q5O`$9|*&4Nx-d2"Vbfrv'%(nASmR!
		$a_01_2 = {5d 36 3c 71 2a 75 27 2d 69 63 7b 31 74 4b 44 7c 3f 24 6c 79 7d 37 23 6b 4e 73 2c 65 33 53 48 20 6e 35 4a 34 41 56 42 70 21 5c 49 38 51 29 54 2f 3a 60 77 4f 55 76 30 22 59 57 68 46 61 5f 26 39 6d 40 4d 62 3b 28 7e 43 2e 58 67 32 6f 7a 5b 72 78 25 52 47 4c 3e 66 3d 45 6a 50 2b 5e 5a 64 } //4 ]6<q*u'-ic{1tKD|?$ly}7#kNs,e3SH n5J4AVBp!\I8Q)T/:`wOUv0"YWhFa_&9m@Mb;(~C.Xg2oz[rx%RGL>f=EjP+^Zd
		$a_01_3 = {34 65 6e 4c 34 6e 29 61 4c 30 34 5b 3c 6e 41 52 4a 4a 39 2f 6e 24 6a 44 } //4 4enL4n)aL04[<nARJJ9/n$jD
		$a_01_4 = {29 39 39 5c 70 34 34 3c 5c 39 4c 61 44 41 4c 2f 44 4a 5e 34 61 5c 3c 2f 5c 29 5c } //4 )99\p44<\9LaDAL/DJ^4a\</\)\
		$a_01_5 = {61 6e 79 47 61 79 47 79 61 6e 22 79 61 6e 79 22 61 79 6e 22 41 61 6e 41 22 50 2b 23 50 2b 23 50 } //4 anyGayGyan"yany"ayn"AanA"P+#P+#P
		$a_01_6 = {59 54 3a 5f 59 74 2a 3c 32 42 3a 5f } //4 YT:_Yt*<2B:_
		$a_01_7 = {62 54 4e 3c 32 37 3a 53 7b 56 7b 69 57 74 5b 79 57 72 51 6f 32 74 50 24 } //4 bTN<27:S{V{iWt[yWrQo2tP$
		$a_01_8 = {2f 73 62 69 6e 2f 73 68 73 } //1 /sbin/shs
		$a_01_9 = {54 48 45 5f 50 41 53 53 } //1 THE_PASS
		$a_01_10 = {5b 57 65 6c 63 6f 6d 65 20 4d 61 73 74 65 72 5d } //1 [Welcome Master]
		$a_01_11 = {73 63 5f 65 6e 63 6f 64 65 } //1 sc_encode
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*4+(#a_01_7  & 1)*4+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=4
 
}