<?php

$sk = oberon_new_secret_key();
$pk = oberon_get_public_key($sk);
$id = "mikelodder";
$token = oberon_new_token($sk, $id);
$blind_token = oberon_add_blinding($token, array(10, 10, 10, 10));

$nonce = array(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
$proof = oberon_create_proof($blind_token, $id, array(array(10, 10, 10, 10)), $nonce);
var_dump(oberon_verify_proof($proof, $pk, $id, $nonce));
