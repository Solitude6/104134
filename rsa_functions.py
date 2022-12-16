import number_theory_functions

class RSA():
    def __init__(self, public_key, private_key = None):
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def generate(digits = 10):
        """
        Creates an RSA encryption system object

        Parameters
        ----------
        digits : The number of digits N should have

        Returns
        -------
        RSA: The RSA system containing:
        * The public key (N,e)
        * The private key (N,d)
        """
        n1 = number_theory_functions.generate_prime(int(digits / 2))
        n2 = number_theory_functions.generate_prime(int(digits / 2))
        N = n1 * n2
        phi = (n1 - 1) * (n2 - 1)
        e = number_theory_functions.generate_prime(int(digits / 2))

        d = number_theory_functions.modular_inverse(e, phi)
        return RSA((N, e), (N, d))

    def encrypt(self, m):
        """
        Encrypts the plaintext m using the RSA system

        Parameters
        ----------
        m : The plaintext to encrypt

        Returns
        -------
        c : The encrypted ciphertext
        """
        c = number_theory_functions.modular_exponent(m, self.public_key[1], self.public_key[0])
        return c


    def decrypt(self, c):
        """
        Decrypts the ciphertext c using the RSA system

        Parameters
        ----------
        c : The ciphertext to decrypt

        Returns
        -------
        m : The decrypted plaintext
       """
        m = number_theory_functions.modular_exponent(c, self.private_key[1], self.private_key[0])
        return m