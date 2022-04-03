//packages
package com.company;

//Imports
import java.lang.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

//Main Class


    //psvm (public static void main) start of program


    //menu class
    class menu {
        public static int e_value;
        //int n
        public static int n_value;
        //int d
        public static int d_value;
        //int Φ (phi)
        public static int phi_value;
        //plaintext m
        public static byte[] m;
        //encrypted ciphertext
        public static int[] c;
        //decrypted message
        public static byte[] d;
        //Title
        private static final String TITLE =
                "\n\n" +
                        " by Vilius Petrauskas and Obertelli,\n" +
                        "Kai \n\n" +
                        "\t********************\n" +
                        "\t2. Unsecure RSA example \n" +
                        "\t1. RSA \n" +
                        "\t0. Exit \n" +
                        "\t********************\n" +

                        "Please input a single digit (0-2):\n";
        //Menu system
        menu() {
            //menu option
            int selected = -1;
            //while user not exited
            while (selected != 0) {
                System.out.println(TITLE);
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                try {
                    selected = Integer.parseInt(in.readLine());
                    switch (selected) {
                        //option 1 = Working RSA
                        case 1:
                            q1();
                            break;
                        //option 2 = Unsecure example with own inputs
                        case 2:
                            q2();
                            break;

                    }
                } catch (Exception ex) {
                }
            } // if 0 end while
            System.out.println("Bye!");
        }

        //q1 RSA
        private void q1() {
            System.out.println("(1) RSA");
            //prime generator
            int primed[] = primes();
            //user input
            System.out.print("Please enter the message you want to send: ");
            Scanner sc = new Scanner(System.in);
            String plaintext = sc.nextLine();
            //plaintext
            m = convertstringintonumber(plaintext);
            //phi (p-1) * (q-1)
            phi_value = phi(primed[0],primed[1]);
            //e
            e_value = e(phi_value);
            //n
            n_value = n(primed[0],primed[1]);
            //d
            d_value = dcal(e_value,phi_value);
            //ciphertext
            c = rsaencrypt(e_value,m,n_value);
            //converted back
            d = rsadecrypt(d_value, c, n_value);

            //Display to console

            //Prime values
            System.out.println("Prime values: " + primed[0]+" , "+primed[1]);
            //e
            System.out.println("e: " + e_value);
            //n
            System.out.println("n: " + n_value);
            //phi
            System.out.println("phi: " + phi_value);
            //d
            System.out.println("d: " + d_value);
            //plaintext array
            System.out.println("m: " + Arrays.toString(m));
            //encrypted array
            System.out.println("c: " + Arrays.toString(c));
            //decrypted array
            System.out.println("decrypted: " + Arrays.toString(d));
            //Decoded message ASCII
            String decode = new String(d,StandardCharsets.UTF_8);
            System.out.println("message: " + decode);


        }

        //q2 RSA (when its unsecure)
        private void q2() {
            //user input
            System.out.println("(2) RSA with user input");
            Scanner sc = new Scanner(System.in);
            Scanner cs = new Scanner(System.in);
            //first prime (p)
            System.out.print("Input the first prime number: ");
            int prime1 = sc.nextInt();
            //second prime (q)
            System.out.print("Input the second prime number: ");
            int prime2 = sc.nextInt();
            //Message m
            System.out.print("Input your message: ");
            String plaintext = cs.nextLine();
            //m (plaintext) --> ASCII value format
            m = convertstringintonumber(plaintext);
            //n
            n_value = n(prime1,prime2);
            //phi
            phi_value = phi(prime1,prime2);
            //e
            e_value = e(phi_value);
            //d
            d_value = dcal(e_value,phi_value);
            //c
            c = rsaencrypt(e_value,m,n_value);
            //decrypted
            d = rsadecrypt(d_value,c,n_value);

            //commandline output
            System.out.println("Prime values: " + prime1+" , "+prime2);
            //e
            System.out.println("e: " + e_value);
            //n
            System.out.println("n: " + n_value);
            //phi
            System.out.println("phi: " + phi_value);
            //d
            System.out.println("d: " + d_value);
            //plaintext array
            System.out.println("m: " + Arrays.toString(m));
            //encrypted array
            System.out.println("c: " +Arrays.toString(c));
            //decrypted array
            System.out.println("decrypted: " + Arrays.toString(d));

        }


    

    //Decryption
    public static byte[] rsadecrypt(int d, int[] c, int n){
        //decrypt = c^d mod n = m
        //(ab) % MOD = ((a % MOD)b) % MOD
        //a^(p-1) mod p = 1, When p is prime.

        //retrun array
        byte[] h = new byte[c.length];

        //for each element in encrypted array c
        for(int i=0;i<c.length;i++)
        {
            //Big integer version of c[i]
            BigInteger B_c = new BigInteger(String.valueOf(c[i]));
            //Big integer version of d
            BigInteger B_d = new BigInteger(String.valueOf(d));
            //Big integer version of n
            BigInteger B_n = new BigInteger(String.valueOf(n));

            //calculating c^d mod n
            BigInteger BigCalc = B_c.modPow(B_d,B_n);
            //adding value to return list
            h[i] = (byte) BigCalc.intValue();

        }
        //return decrypted array
        return h;

    }

    //encryption
    public static int[] rsaencrypt(int e, byte[] m, int n){
        //Encrypt = m^e mod n = c

        //return array h
        int[] h = new int[m.length];

        //for each element in plaintext array m
        for(int i=0;i<m.length;i++)
        {
            //Big integer version of m[i]
            BigInteger B_m = new BigInteger(String.valueOf(m[i]));
            //Big integer version of d
            BigInteger B_e = new BigInteger(String.valueOf(e));
            //Big integer version of n
            BigInteger B_n = new BigInteger(String.valueOf(n));

            //calculating m^e mod n
            BigInteger BigCalc = B_m.modPow(B_e,B_n);

            //adding value to return list
            h[i] = BigCalc.intValue();
        }
        //return encrypted array c
        return h;

    }

    //convert string to numbers
    public static byte[] convertstringintonumber(String a)
    {
        //plaintext
        String plaintext = a;
        //array of ASCII values (equivalent to plaintext)
        byte[] arr = plaintext.getBytes(StandardCharsets.UTF_8);
        //return arr
        return arr;
    }

    //calculating d
    public static int dcal(int e , int phi )
    {
        //e = e mod phi
        e = e % phi;
        //mod inverse
        for (int x = 1; x < phi; x++)
            if ((e * x) % phi == 1)
                return x;
        return 1;
    }

    //phi calculator
    public static int phi (int p ,int q)
    {
        return ( p - 1)*(q-1);
    }

    //e
    public static int e(int phi)
    {
        int e;
        for( e=2;e< phi;e++ )
        {
            //find value e that is relatively prime with phi
            if(gcd(e,phi)==1)
            {
                break;
            }
        }

        return e;

    }

    //gcd calc
    static double gcd(int e, int z)
    {
        if (e == 0)
            return z;
        else
            return gcd(z % e, e);
    }

    //n calc
    public static int n(int p, int q)
    {
        return p*q;
    }

    //Primes generator
    public static int[] primes()
    {
        int low = 0;
        int high = 0;


        Random rand = new Random();
        while (low == high) {
            //to get rand.nextInt in certain range -> ((max - min) + 1 ) + min

            //min range 17 max range 117
            low = rand.nextInt((100-17)+1) +17;
            while (!isPrime(low))
            {
                low = rand.nextInt((100-17)+1) + 17;
            }
            //min range 19 max range 119
            high = rand.nextInt((100 - 19)+1) + 19;
            while (!isPrime(high)) {
                high = rand.nextInt((100-19)+1) + 19;
            }
        }
        //return primes
        return new int[] {low,high};
    }

    //Check if prime
    private static boolean isPrime(int inputNum) {
        if (inputNum <= 3 || inputNum % 2 == 0)
            return inputNum == 2 || inputNum == 3;
        int divisor = 3;
        while ((divisor <= Math.sqrt(inputNum)) && (inputNum % divisor != 0))
            divisor += 2;

        return inputNum % divisor != 0;

    }
    public static void main(String[] args) {
        //start menu
        new menu();

    }
}