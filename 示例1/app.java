public static  void main(String[] args) throws Exception{
        byte[] encrypt = AESEncryptUtil.encrypt("HZT_2020".getBytes(), "123");
        String s = DatatypeConverter.printHexBinary(encrypt);
        System.out.println(s);
        byte[] bytes = DatatypeConverter.parseHexBinary(s);
        byte[] decrypt = AESEncryptUtil.decrypt(bytes, "123");
        String mm = new String(decrypt,"UTF-8");
        System.out.println(mm);

    }
