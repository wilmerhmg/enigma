<?php

class sqAES{
    /**
     * decrypt AES 256
     * @param string $password
     * @param data $edata
     * @return Informacion legible por humanos
     */
    public static function decrypt($password, $edata){
        $data = base64_decode($edata);
        $salt = substr($data, 8, 8);
        $ct = substr($data, 16);

        /**
         * From https://github.com/mdp/gibberish-aes
         *
         * El número de rondas depende del tamaño del AES en uso
         * 3 Ciclos para 256
         *        2 2 rondas para la llave, 1 para la IV
         * 2 Ciclos para 128
         *        1 ronda para la llave, 1 ronda para la IV
         * 3 rondas para 192 ya que no está dividido por 128 bits
         */
        $rounds = 3;
        $data00 = $password.$salt;
        $sha2_hash = array();
        $sha2_hash[0] = hash('md5', $data00, true);
        $result = $sha2_hash[0];

        for ($i = 1; $i < $rounds; $i++) {
            $sha2_hash[$i] = hash('md5', $sha2_hash[$i - 1].$data00, true);
            $result .= $sha2_hash[$i];
        }

        $key = substr($result, 0, 32);
        $iv  = substr($result, 32, 16);

        return openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
    }

    /**
     * crypt AES 256
     *
     * @param string $password
     * @param data $data
     *
     * @return Datos cifrados base64
     */
    public static function crypt($password, $data){
        // Establecer una semilla aleatoria
        $salt = openssl_random_pseudo_bytes(8);

        $salted = '';
        $dx = '';

        // Semilla en la llabe(32) y un IV de (16) = 48
        while (strlen($salted) < 48) {
            $dx = hash('md5',$dx.$password.$salt, true);
            $salted .= $dx;
        }

        $key = substr($salted, 0, 32);
        $iv  = substr($salted, 32, 16);

        $encrypted_data = openssl_encrypt($data, 'aes-256-cbc', $key, true, $iv);

        return base64_encode('Salted__'.$salt.$encrypted_data);
    }
}
