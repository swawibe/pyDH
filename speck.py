def new(key, IV):
    return Python_SPECK(key, IV)


class Python_SPECK():
    
    def __init__(self, key, IV):
        
        self.isBlockCipher = True
        self.isAEAD = False
        self.block_size = 16
        self.implementation = 'python'
        
        #convert the key bytesarray to int
        self.key = self.bytesToNumber(key)
        
        self.IV = IV
        self.rounds = 32
        self.word_size = 64
        self.k = list()
        self.key_words = 2
        
        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1        
        
        #The following parameters are valid when having SPECK with 128bits size blocks and 128 bit key size
        self.alpha_shift = 8
        self.beta_shift = 3
        
        
        # Parse the given key and truncate it to the key length
        try:
            self.key = self.key & ((2 ** 128) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [(self.key >> (x * self.word_size)) & self.mod_mask for x in
                      xrange(1, 128 // self.word_size)]

        for x in xrange(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])
            
      
       
    # ROR(x, r) ((x >> r) | (x << (64 - r)))
    def ROR(self,x):
        rs_x = ((x >> self.alpha_shift) | (x << (self.word_size - self.alpha_shift)))& self.mod_mask
        return rs_x


    #ROL(x, r) ((x << r) | (x >> (64 - r)))
    def ROL(self,x):
        ls_x = ((x << self.beta_shift) | (x >> (self.word_size - self.beta_shift)))& self.mod_mask
        return ls_x


    # ROR(x, r) ((x >> r) | (x << (64 - r)))
    def ROR_inv(self,x):
        rs_x = ((x >> self.beta_shift) | (x << (self.word_size - self.beta_shift)))& self.mod_mask
        return rs_x


    #ROL(x, r) ((x << r) | (x >> (64 - r)))
    def ROL_inv(self,x):
        ls_x = ((x << self.alpha_shift) | (x >> (self.word_size - self.alpha_shift)))& self.mod_mask
        return ls_x


    def bytesToNumber(self,b):
        total = 0
        multiplier = 1
        for count in xrange(len(b)-1, -1, -1):
            byte = b[count]
            total += multiplier * byte
            multiplier *= 256
        return total


    def numberToByteArray(self,n, howManyBytes=None):
        """Convert an integer into a bytearray, zero-pad to howManyBytes.
    
        The returned bytearray may be smaller than howManyBytes, but will
        not be larger.  The returned bytearray will contain a big-endian
        encoding of the input integer (n).
        """    
        if howManyBytes == None:
            howManyBytes = numBytes(n)
        b = bytearray(howManyBytes)
        for count in xrange(howManyBytes-1, -1, -1):
            b[count] = int(n % 256)
            n >>= 8
        return b


    # define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
        
    def encrypt_round(self, x, y, k):
        #Feistel Operation
        new_x = self.ROR(x)   #x = ROR(x, 8)
        new_x = (new_x + y) & self.mod_mask
        new_x ^= k 
        new_y = self.ROL(y)    #y = ROL(y, 3)
        new_y ^= new_x

        return new_x, new_y
    

    def decrypt_round(self, x, y, k):
        #Inverse Feistel Operation
                
        xor_xy = x ^ y     
        new_y = self.ROR_inv(xor_xy) 
        xor_xk = x ^ k

        msub = (xor_xk - new_y) & self.mod_mask
        new_x = self.ROL_inv(msub) 

        return new_x, new_y
   
  
    
    def encrypt(self, plaintext):        
        
        plaintextBytes = plaintext[:]
        chainBytes = self.IV[:]      
      
        #CBC Mode: For each block...
        for x in xrange(len(plaintextBytes)//self.block_size):
            
            #XOR with the chaining block
            blockBytes = plaintextBytes[x*self.block_size : (x*self.block_size)+self.block_size]
            
            for y in xrange(self.block_size):
                blockBytes[y] ^= chainBytes[y]

            blockBytesNum = self.bytesToNumber(blockBytes)
            b = (blockBytesNum >> self.word_size) & self.mod_mask
            a = blockBytesNum & self.mod_mask
                
            for i in self.key_schedule:
                b, a = self.encrypt_round(b, a, i)
         
            ciphertext = (b << self.word_size) | a                
            ciphertext= self.numberToByteArray(ciphertext,howManyBytes=self.block_size) 
            
                
            #Overwrite the input with the output
            for y in xrange(self.block_size):
                plaintextBytes[(x*self.block_size)+y] = ciphertext[y]

            #Set the next chaining block
            chainBytes = ciphertext

        
        self.IV = chainBytes[:]
        return bytearray(plaintextBytes)
           

    def decrypt(self, ciphertext):
        
        
        ciphertextBytes = ciphertext[:]
        chainBytes = self.IV[:]


        #CBC Mode: For each block...
        for x in xrange(len(ciphertextBytes)//self.block_size):

            #Decrypt it
            blockBytes = ciphertextBytes[x*self.block_size : (x*self.block_size)+self.block_size]
               
            ciphertext = self.bytesToNumber(blockBytes)
            b = (ciphertext >> self.word_size) & self.mod_mask
            a = ciphertext & self.mod_mask        
           
            for i in reversed(self.key_schedule):
                b, a = self.decrypt_round(b, a, i)
          
            plaintext = (b << self.word_size) | a      
            plaintext = self.numberToByteArray(plaintext,howManyBytes=self.block_size)  
            
            #XOR with the chaining block and overwrite the input with output
            for y in xrange(self.block_size):
                plaintext[y] ^= chainBytes[y]
                ciphertextBytes[(x*self.block_size)+y] = plaintext[y]

            #Set the next chaining block
            chainBytes = blockBytes

        self.IV = chainBytes[:]

        return bytearray(ciphertextBytes)



if __name__== '__main__':
    
    plaintext = bytearray("This is a test of Speck cipher. This is a test of Speck cipher. This is a test of Speck cipher. This is a test of Speck cipher. This is a test of Speck cipher. This is a test of Speck cipher. This is a test of Speck cipher. This is a test of Speck cipher. ")

    print("Initial Plaintext :", plaintext, "length of plaintext", len(plaintext))
    

    key = bytearray("20697971583088482630959689854833034657954459914412189905379253094900218203676121841247503108053106647257254058502653753274504275")
    IV  = bytearray("abcdefghijklmnopqrstuvwxyzabcdef")
    
    encryption =  Python_SPECK(key, IV)

    ciphertext = encryption.encrypt(plaintext)
    print("After cipher :", ciphertext, "length of ciphertext", len(ciphertext))
     
   
    decryption =  Python_SPECK(key, IV)   
        
    Recovered_plaintext=decryption.decrypt(ciphertext)
    print("Decrypted Cipher Block :", Recovered_plaintext, "length of Decrypted text", len(Recovered_plaintext))
    