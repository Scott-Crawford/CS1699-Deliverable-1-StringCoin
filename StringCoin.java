import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;

public class StringCoin{
    
    private static final String BILL_PUBLIC_KEY = "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10";
    
    private static final String BILL_PRIVATE_KEY = "3081c60201003081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca404160214556d46e1888b30bccf9c4a5ea71b41c107b5d219";
    
    public static void main(String[] args) throws Exception{
        try{
            if(args.length!=1){
                throw new InvalidDataException("No file provided.");
            }
            BufferedReader infile = new BufferedReader(new FileReader(args[0]));
            HashMap<String, String> coinTracker= new HashMap<String, String>();
            int blockCount = 0;
            String prevBlockHash = "0";
            while (infile.ready()) {
                String block  = new String(infile.readLine().getBytes());
                String[] blockElements = block.split(",");
                if(blockCount == 0){
                    if(!blockElements[0].equals("0")){
                        throw new InvalidDataException("First element of the Genesis block is not equal to 0.");
                    }
                }
                else{
                    if(!blockElements[0].equals(prevBlockHash)){
                        throw new InvalidDataException("Invalid hash: " + blockElements[0] + " does not match " + prevBlockHash+".");
                    }
                }
                if(blockElements[1].equals("CREATE")){
                    if(coinTracker.containsKey(blockElements[2])){
                        throw new InvalidDataException("Invalid coin: Coin " + blockElements[2] + " already exists.");
                    }
                    else if(!verifyMessage(blockElements[2],blockElements[3],BILL_PUBLIC_KEY)){
                        throw new InvalidDataException("Invalid coin " + blockElements[2] + ".");
                    }
                    else{
                        String message = blockElements[0]+","+blockElements[1]+","+blockElements[2]+","+blockElements[3];
                        if(!verifyMessage(message, blockElements[4], BILL_PUBLIC_KEY)){
                            throw new InvalidDataException("Invalid line " + message + ".");
                        }
                        coinTracker.put(blockElements[2], BILL_PUBLIC_KEY);
                    }
                }
                else if(blockElements[1].equals("TRANSFER")){
                    if(!coinTracker.containsKey(blockElements[2])){
                        throw new InvalidDataException("Invalid coin: Coin " + blockElements[2] + "doesn't exist.");
                    }
                    else{
                        String coinHolder = coinTracker.get(blockElements[2]);
                        String message = blockElements[0]+","+blockElements[1]+","+blockElements[2]+","+blockElements[3];
                        if(!verifyMessage(message, blockElements[4], coinHolder)){
                            throw new InvalidDataException("Invalid line " + message + ".");
                        }
                        coinTracker.replace(blockElements[2], blockElements[3]);
                    }
                }
                else{
                    throw new InvalidDataException("Invalid block type.");
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
        catch(InvalidDataException e){
            e.printStackTrace();
            System.exit(1);
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

class InvalidDataException extends Exception{
    public InvalidDataException(String errorMessage){
        super(errorMessage);
    }
}
