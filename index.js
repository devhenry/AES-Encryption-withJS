  
  
 
  var crypt = {
   
    secret : "tuakanaChe333",
    
    // (B2) ENCRYPT
    encrypt : function (clear) {
      var cipher = CryptoJS.AES.encrypt(clear, crypt.secret);
      cipher = cipher.toString();
      return cipher;
    },

      // (B3) DECRYPT
      decrypt : function (cipher) {
        var decipher = CryptoJS.AES.decrypt(cipher, crypt.secret);
        decipher = decipher.toString(CryptoJS.enc.Utf8);
        return decipher;
      }
  };
 
  function encrypt(){
    
    var mypass = document.getElementById('password').value;

    var cipher = crypt.encrypt(mypass);
    document.getElementById("encryptedRes").innerHTML = `<b>The Encrypted text is :</b>${cipher}`;
   

    var decipher = crypt.decrypt(cipher);
    document.getElementById("decryptedRes").innerHTML = `<b>The Decrypted text is :</b> ${decipher}`;

  }
 
 

