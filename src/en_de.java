import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
/**
 *
 * @author Admin
 */

public final class en_de extends javax.swing.JFrame {
    String  passwordToHash;
    public en_de() throws NoSuchAlgorithmException, InvalidKeySpecException {
        initComponents();
        contrasenya();
        Encriptacion();
        VerificacionP(); 
        
    }

public void contrasenya(){
    System.out.println("Contraseña = " + "password");
}
// 1.1.-Metodo de encriptacion 
public void Encriptacion() throws NoSuchAlgorithmException, InvalidKeySpecException{
    //Creacion de contraseña
    String  ContrasenyaOriginal = "password";
    //Metodo (GeneradorSeguroContrasenyaHash) de encriptacion "SHA1PRNG"
        String GeneradorSeguroContrasenyaHash = generateStorngPasswordHash(ContrasenyaOriginal);
    System.out.println("generatedSecuredPasswordHash = " + GeneradorSeguroContrasenyaHash);
}
//1.2.-metodo de encriptacion
private static String generateStorngPasswordHash(String Contrasenya) throws NoSuchAlgorithmException, InvalidKeySpecException{
    int iterations = 1000;
    char[] chars = Contrasenya.toCharArray();
    byte[] salt = getSalt();

    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

    byte[] hash = skf.generateSecret(spec).getEncoded();
    return iterations + ":" + toHex(salt) + ":" + toHex(hash);
}
//1.3.-algorimo de encriptacion
private static byte[] getSalt() throws NoSuchAlgorithmException{
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    byte[] salt = new byte[16];
    sr.nextBytes(salt);
    return salt;
}
//1.4.-ni puta idea
private static String toHex(byte[] array) throws NoSuchAlgorithmException{
    BigInteger bi = new BigInteger(1, array);
    String hex = bi.toString(16);
    
    int paddingLength = (array.length * 2) - hex.length();
    if(paddingLength > 0)
    {
        return String.format("%0"  +paddingLength + "d", 0) + hex;
    }else{
        return hex;
    }
}

//2.1.-Metodo de verificacion para saber si es correcto o incorrecto
public void VerificacionP() throws NoSuchAlgorithmException, InvalidKeySpecException {
    String  ContrasenyaOriginal = "password";

    String GeneradorSeguroContrasenyaHash = generateStorngPasswordHash(ContrasenyaOriginal);
    System.out.println("generatedSecuredPasswordHash = " + GeneradorSeguroContrasenyaHash);

    boolean matched = ValidadorContraseya("password", GeneradorSeguroContrasenyaHash);
    System.out.println(matched);

    matched = ValidadorContraseya("password1", GeneradorSeguroContrasenyaHash);
    System.out.println(matched);
}
//2.2.-Validacion de la contraseña
private static boolean ValidadorContraseya(String ContrasenyaOriginal, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException{
    String[] parts = storedPassword.split(":");
    int iterations = Integer.parseInt(parts[0]);

    byte[] salt = fromHex(parts[1]);
    byte[] hash = fromHex(parts[2]);

    PBEKeySpec spec = new PBEKeySpec(ContrasenyaOriginal.toCharArray(), 
        salt, iterations, hash.length * 8);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] testHash = skf.generateSecret(spec).getEncoded();

    int diff = hash.length ^ testHash.length;
    for(int i = 0; i < hash.length && i < testHash.length; i++){
        diff |= hash[i] ^ testHash[i];
    }
    return diff == 0;
}
//2.3.-ni puta idea
private static byte[] fromHex(String hex) throws NoSuchAlgorithmException{
    byte[] bytes = new byte[hex.length() / 2];
    for(int i = 0; i < bytes.length ;i++){
        bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
    }
    return bytes;
}



    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel_Ver = new javax.swing.JLabel();
        jLabel_Esconder = new javax.swing.JLabel();
        jPasswordField1 = new javax.swing.JPasswordField();
        jLabel1 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel_Ver.setText("Ver");
        jLabel_Ver.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jLabel_VerMouseClicked(evt);
            }
        });

        jLabel_Esconder.setText("Esconder");
        jLabel_Esconder.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jLabel_EsconderMouseClicked(evt);
            }
        });

        jLabel1.setText("CONTRASEÑA  :");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jLabel_Esconder, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel_Ver, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(96, 96, 96))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(191, 191, 191)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel_Ver)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel_Esconder)))
                .addContainerGap(70, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jLabel_VerMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel_VerMouseClicked
        jLabel_Ver.setVisible(false);
        jLabel_Esconder.setVisible(true);
        jPasswordField1.setEchoChar((char)0); 
    }//GEN-LAST:event_jLabel_VerMouseClicked

    private void jLabel_EsconderMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel_EsconderMouseClicked
        jLabel_Ver.setVisible(true);
        jLabel_Esconder.setVisible(false);
        jPasswordField1.setEchoChar('•'); 
    }//GEN-LAST:event_jLabel_EsconderMouseClicked


    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(en_de.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(en_de.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(en_de.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(en_de.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    new en_de().setVisible(true);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                    Logger.getLogger(en_de.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel_Esconder;
    private javax.swing.JLabel jLabel_Ver;
    private javax.swing.JPasswordField jPasswordField1;
    // End of variables declaration//GEN-END:variables
}
