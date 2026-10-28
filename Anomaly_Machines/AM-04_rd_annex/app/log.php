<?php
// DIRECTIVE ZERO — AM-04 app/log.php
//
// The Log class — the PHP object injection gadget.
// __destruct() calls file_put_contents with attacker-controlled
// filename and data. Players who craft a serialized Log object
// with a webshell payload and POST it as `param` to index.php
// get a webshell written to the webroot.

class Log
{
    public $filename = '';
    public $data = '';

    public function __construct()
    {
        $this->filename = '';
        $this->data = '';
    }

    public function PrintLog()
    {
        $pre = "[LOG]";
        $now = date('Y-m-d H:i:s');
        $str = '$pre - $now - $this->data';
        eval("\$str = \"$str\";");
        echo $str;
    }

    public function __destruct()
    {
        file_put_contents($this->filename, $this->data, FILE_APPEND);
    }
}