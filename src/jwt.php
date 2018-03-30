<?php

 /**
  * Json Web Token
  * @author Gert-Jan Wille <gertjanwille.w@gmail.com>
  */

 class JWT {

   static function getTime() {
     $date = new DateTime();
     return $date->getTimestamp();
   }

   static function create($payload = [], $secret, $exp = 172800) {

     $header = [
       'typ' => 'JWT',
       'alg' => 'HS256'
     ];

     $header = json_encode($header);
     $header = base64_encode($header);

     $extra_payload = array(
        "iss" => $_SERVER[HTTP_HOST],
        "aud" => $_SERVER[HTTP_HOST],
        "iat" => JWT::getTime(),
        "exp" => JWT::getTime() + $exp
     );

     $payload = array_merge($payload, $extra_payload);
     $payload = json_encode($payload);
     $payload = base64_encode($payload);

     // Generates a keyed hash value using the HMAC method
     $signature = hash_hmac('sha256',$header.".".$payload, $secret, true);

     //base64 encode the signature
     $signature = base64_encode($signature);

     //concatenating the header, the payload and the signature to obtain the JWT token
     $token = "$header.$payload.$signature";

     return $token;
   }

   static function verify($token, $secret) {
     $expToken = explode(".", $token);

     $signature = hash_hmac('sha256',"$expToken[0].$expToken[1]", $secret, true);
     $signature = base64_encode($signature);

     $compareToken = "$expToken[0].$expToken[1].$signature";


     return $token == $compareToken && JWT::isValid($token);
   }

   static function isValid($token) {
     $payload = (array)json_decode(base64_decode(explode(".", $token)[1]));
     return $payload['exp'] > JWT::getTime();
   }

   static function isAdmin($token, $secret) {
     $payload = (array)json_decode(base64_decode(explode(".", $token)[1]));
     return JWT::verify($token, $secret) ? $payload['isAdmin'] : 0;
   }

   static function content($token, $secret) {
     $payload = (array)json_decode(base64_decode(explode(".", $token)[1]));
     return JWT::verify($token, $secret) ? $payload : [];
   }
 }
