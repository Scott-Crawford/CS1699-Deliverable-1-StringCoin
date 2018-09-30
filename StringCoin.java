import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;

public class StringCoin{
    
    private static final String BILL_PUBLIC_KEY = "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10";
    
    private static final String BILL_PRIVATE_KEY = "3081c60201003081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca404160214556d46e1888b30bccf9c4a5ea71b41c107b5d219";
    
    public static void main(String[] args) throws Exception{
        if(args.length!=1){
            System.out.println("Give a file");
            System.exit(0);
        }
        BufferedReader infile = new BufferedReader(new FileReader(args[0]));
        HashMap<String, String> coinTracker= new HashMap<String, String>();
        int blockCount = 0;
        String prevBlockHash = "";
        while (infile.ready()) {
            String block  = infile.readLine();
            String[] blockElements = block.split(",");
            if(blockCount == 0){
                if(!blockElements[0].equals("0")){
                    System.out.println("Bad Genesis");
                    System.exit(0);
                }
            }
            else{
                if(!blockElements[0].equals(prevBlockHash)){
                    System.out.println("Bad Prev Hash");
                    System.exit(0);
                }
            }
            if(blockElements[1].equals("CREATE")){
                if(coinTracker.containsKey(blockElements[2])){
                    System.out.println("Creating an exisiting coin");
                    System.exit(0);
                }
                else if(!verifyMessage(blockElements[2],blockElements[3],BILL_PUBLIC_KEY)){
                    System.out.println("Invalid Coin Creation");
                    System.exit(0);
                }
                else{
                    String message = blockElements[0]+","+blockElements[1]+","+blockElements[2]+","+blockElements[3];
                    if(!verifyMessage(message, blockElements[4], BILL_PUBLIC_KEY)){
                        System.out.println("Not a valid signature");
                        System.exit(0);
                    }
                    coinTracker.put(blockElements[2], BILL_PUBLIC_KEY);
                }
            }
            else if(blockElements[1].equals("TRANSFER")){
                if(!coinTracker.containsKey(blockElements[2])){
                    System.out.println("This coin doesn't exist");
                    System.exit(0);
                }
                else{
                    String coinHolder = coinTracker.get(blockElements[2]);
                    String message = blockElements[0]+","+blockElements[1]+","+blockElements[2]+","+blockElements[3];
                    if(!verifyMessage(message, blockElements[4], coinHolder)){
                        System.out.println("Not a valid signature");
                        System.exit(0);
                    }
                    coinTracker.replace(blockElements[2], blockElements[3]);
                }
            }
            else{
                System.out.println("WHAT ARE YOU DOING");
                System.exit(0);
            }
            prevBlockHash = calculateHash(block);
            blockCount++;
        }	
		infile.close();
        ArrayList<String> coins = new ArrayList<String>();
        coins.addAll(coinTracker.keySet());
        Collections.sort(coins);
        for(String coin : coins){
            System.out.println("Coin "+coin+" / Owner "+coinTracker.get(coin));
        }
    }
    
    public static String calculateHash(String x) {
        if (x == null) {
            return "0";
        }
        byte[] hash = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(x.getBytes());
        } catch (NoSuchAlgorithmException nsaex) {
            System.err.println("No SHA-256 algorithm found.");
            System.err.println("This generally should not happen...");
            System.exit(1);
        }
        return convertBytesToHexString(hash);
    }
    
    public static boolean verifyMessage(String msg, String sig, String key) throws Exception {
        PublicKey pk = loadPublicKey(key);
        byte[] sigBytes = convertHexToBytes(sig);
        boolean toReturn = verify(msg, sigBytes, pk);
        return toReturn;
    }
    
    public static boolean verify(String toCheck, byte[] sig, PublicKey pk) throws Exception {
	    Signature sig2 = Signature.getInstance("SHA1withDSA", "SUN");
	    byte[] bytes = toCheck.getBytes();
	    sig2.initVerify(pk);
	    sig2.update(bytes, 0, bytes.length);
	    return sig2.verify(sig);
    }
    
    public static byte[] convertHexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        int c = 0;
        for (int j = 0; j < hex.length(); j += 2) {
            String twoHex = hex.substring(j, j + 2);
            byte byteVal = (byte) Integer.parseInt(twoHex, 16);
            bytes[c++] = byteVal;
        }
        return bytes;
    }
    
    public static String convertBytesToHexString(byte[] bytes) {
        StringBuffer toReturn = new StringBuffer();
        for (int j = 0; j < bytes.length; j++) {
            String hexit = String.format("%02x", bytes[j]);
            toReturn.append(hexit);
        }
        return toReturn.toString();
    }
    
    public static PublicKey loadPublicKey(String stored) throws Exception {
    	byte[] data = convertHexToBytes(stored);
    	X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
    	KeyFactory fact = KeyFactory.getInstance("DSA");
    	return fact.generatePublic(spec);
    }
}
