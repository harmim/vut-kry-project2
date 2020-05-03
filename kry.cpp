/**
 * VUT FIT KRY 2020 2. Project - RSA
 *
 * @author Dominik Harmim <harmim6@gmail.com>
 * @date 30.4.2020
 */


#include <cstdlib>
#include <iostream>
#include <cstring>
#include <string>
#include <cstdio>
#include <ctime>
#include <cmath>
#include <gmpxx.h>


using namespace std;


/**
 * A class that represents en exception during of the processing the RSA
 * algorithm.
 */
class RsaException : public logic_error
{
public:
	/**
	 * Constructs the RsaException with an error message.
	 *
	 * @param msg An error message of the exception.
	 */
	explicit RsaException(const string &msg) : logic_error(msg)
	{}
};


/**
 * A class that represents attributes and operations of the RSA algorithm.
 */
class Rsa
{
public:
	/**
	 * Constructs a class that represents the RSA algorithm with given
	 * parameters.
	 *
	 * @param argc The number of input arguments.
	 * @param argv Values of input arguments.
	 * @throw RsaException if input arguments are not valid.
	 */
	Rsa(const int argc, const char *const argv[])
	{
		static const string invalid_args_msg =
			"Error: invalid arguments."
			" Expecting: -g B | -e E N M | -d D N C | -b E N C";

		if (argc < 2 || strlen(argv[1]) != 2 || argv[1][0] != '-')
		{
			throw RsaException(invalid_args_msg);
		}

		string err_msg;
		const auto op = static_cast<Operation>(argv[1][1]);
		switch (op)
		{
			case Operation::GENERATE:
				if (argc != 3)
				{
					throw RsaException(invalid_args_msg);
				}

				err_msg =
					"Error: A required size of a public modulus (B) should be"
					" a number of bits > 6.";
				try
				{
					b = stoul(argv[2]);
				}
				catch (const exception &e)
				{
					throw RsaException(err_msg);
				}
				if (b <= 6)
				{
					throw RsaException(err_msg);
				}

				operation = Operation::GENERATE;
				break;

			case Operation::ENCRYPT:
			case Operation::DECRYPT:
			case Operation::BREAK:
				if (argc != 5)
				{
					throw RsaException(invalid_args_msg);
				}

				switch (op)
				{
					case Operation::ENCRYPT:
						operation = Operation::ENCRYPT;
						err_msg =
							"Error: arguments E, N, M should be hexadecimal"
							" numbers (prefix 0x or 0X).";
						break;

					case Operation::DECRYPT:
						operation = Operation::DECRYPT;
						err_msg =
							"Error: arguments D, N, C should be hexadecimal"
							" numbers (prefix 0x or 0X).";
						break;

					case Operation::BREAK:
						operation = Operation::BREAK;
						err_msg =
							"Error: arguments E, N, C should be hexadecimal"
							" numbers (prefix 0x or 0X).";
						break;

					default:
						break;
				}
				if (!is_hex(argv[2]) || !is_hex(argv[3]) || !is_hex(argv[4]))
				{
					throw RsaException(err_msg);
				}

				try
				{
					switch (op)
					{
						case Operation::ENCRYPT:
							e = mpz_class(argv[2]);
							n = mpz_class(argv[3]);
							m = mpz_class(argv[4]);
							break;

						case Operation::DECRYPT:
							d = mpz_class(argv[2]);
							n = mpz_class(argv[3]);
							c = mpz_class(argv[4]);
							break;

						case Operation::BREAK:
							e = mpz_class(argv[2]);
							n = mpz_class(argv[3]);
							c = mpz_class(argv[4]);
							break;

						default:
							break;
					}
				}
				catch (const exception &e)
				{
					throw RsaException(err_msg);
				}

				if (n == 0)
				{
					err_msg = "A public modulus (N) can not be 0.";
					throw RsaException(err_msg);
				}

				break;

			default:
				throw RsaException(invalid_args_msg);
		}

		unsigned long seed;
		FILE *urandom = fopen("/dev/urandom", "r");
		if (urandom)
		{
			fread(&seed, sizeof(seed), 1, urandom);
		}
		else
		{
			seed = static_cast<unsigned long>(time(nullptr));
		}
		rand.seed(seed);
	}


	/**
	 * Performs a specified RSA operation.
	 */
	auto do_operation() -> void
	{
		switch (operation)
		{
			case Operation::GENERATE:
				generate();
				gmp_printf(
					"%#Zx %#Zx %#Zx %#Zx %#Zx\n",
					p.get_mpz_t(),
					q.get_mpz_t(),
					n.get_mpz_t(),
					e.get_mpz_t(),
					d.get_mpz_t()
				);
				break;

			case Operation::ENCRYPT:
				encrypt();
				gmp_printf("%#Zx\n", c.get_mpz_t());
				break;

			case Operation::DECRYPT:
				decrypt();
				gmp_printf("%#Zx\n", m.get_mpz_t());
				break;

			case Operation::BREAK:
				for (size_t i = 0; i < 20; i++)
				{
					try
					{
						factorise();
						break;
					}
					catch (const RsaException &e)
					{
						if (i < 19)
						{
							continue;
						}

						const string err_msg =
							"The factorisation of the public modulus has"
							" failed.";
						throw RsaException(err_msg);
					}
				}

				gmp_printf(
					"%#Zx %#Zx %#Zx\n",
					p.get_mpz_t(),
					q.get_mpz_t(),
					m.get_mpz_t()
				);
				break;
		}
	}


private:
	/**
	 * Possible operations to be performed.
	 */
	enum class Operation : const char
	{
		GENERATE = 'g', /// generation of keys
		ENCRYPT = 'e', /// encryption
		DECRYPT = 'd', /// decryption
		BREAK = 'b', /// breaking the RSA
	};


	/// A GMP interface for random functions.
	gmp_randclass rand = gmp_randclass(gmp_randinit_mt);
	Operation operation; /// An operation to be performed.
	mp_bitcnt_t b = 0; /// A required size of a public modulus.
	mpz_class p; /// The first prime number.
	mpz_class q; /// The second prime number.
	mpz_class n; /// A public modulus.
	mpz_class e; /// A public exponent.
	mpz_class d; /// A private exponent.
	mpz_class m; /// A decrypted message.
	mpz_class c; /// An encrypted message.


	/**
	 * Generates RSA keys.
	 */
	auto generate() -> void
	{
		const mp_bitcnt_t p_length = ceil(b / 2.), q_length = b - p_length;
		while (true)
		{
			p = generate_prime(p_length);
			q = generate_prime(q_length);

			if (p == q)
			{
				continue;
			}

			n = p * q;

			if (mpz_sizeinbase(n.get_mpz_t(), 2) == b)
			{
				break;
			}
		}

		const mpz_class h = (p - 1) * (q - 1);
		do
		{
			e = 2 + rand.get_z_range(h - 2);
		}
		while (gcd(e, h) != 1);
		d = inv(e, h);
	}


	/**
	 * Encrypts the message.
	 */
	auto encrypt() -> void
	{
		mpz_powm(c.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
	}


	/**
	 * Decrypts the message.
	 */
	auto decrypt() -> void
	{
		mpz_powm(m.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
	}


	/**
	 * Factorises the public modulus using the Pollard Rho Brent Integer
	 * Factorisation algorithm. Furthermore, it computes both private prime
	 * numbers, and the private exponent. Finally, it decrypts the message.
	 *
	 * @throw RsaException if the factorisation has failed.
	 */
	auto factorise() -> void
	{
		if (n == 1)
		{
			p = n;
		}
		else if (n % 2 == 0)
		{
			p = 2;
		}
		else
		{
			mpz_class
				y = 1 + rand.get_z_range(n - 1),
				g = 1, r = 1, _q = 1,
				x, k, ys;
			const mpz_class
				_c = 1 + rand.get_z_range(n - 1),
				_m = 1 + rand.get_z_range(n - 1);

			while (g == 1)
			{
				x = y;
				for (mpz_class i = 0; i < r; i++)
				{
					y = (y * y % n + _c) % n;
				}

				k = 0;
				while (k < r && g == 1)
				{
					ys = y;
					for (mpz_class i = 0; i < (_m <= r - k ? _m : r - k); i++)
					{
						y = (y * y % n + _c) % n;
						_q = _q * abs(x - y) % n;
					}
					g = gcd(_q, n);
					k += _m;
				}

				r *= 2;
			}

			if (g == n)
			{
				while (true)
				{
					ys = (ys * ys % n + c) % n;
					g = gcd(abs(x - ys), n);

					if (g > 1)
					{
						break;
					}
				}
			}

			if (g == n)
			{
				const string err_msg =
					"The factorisation of the public modulus has failed.";
				throw RsaException(err_msg);
			}

			p = g;
		}

		q = n / p;
		d = inv(e, (p - 1) * (q - 1));
		decrypt();
	}


	/**
	 * Checks whether a given string is a hexadecimal number.
	 *
	 * @param s A string to be checked whether it is a hexadecimal number.
	 * @return True if a given string is a hexadecimal number, false otherwise.
	 */
	static auto is_hex(const char s[]) -> bool
	{
		return strlen(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
	}


	/**
	 * Computes a greatest common divisor (GCD) of two numbers using
	 * the Euclid's algorithm.
	 *
	 * @param x The first argument of the GCD.
	 * @param y The second argument of the GCD.
	 * @return A greatest common divisor (GCD) of two numbers.
	 * @throw RsaException if arguments are not valid.
	 */
	static auto gcd(const mpz_class &x, const mpz_class &y) -> mpz_class
	{
		if (x <= 0 || y <= 0)
		{
			const string err_msg =
				"Parameters `x` and `y` of the GCD function should be > 0.";
			throw RsaException(err_msg);
		}

		mpz_class s = x, t = y, div;
		while (s > 0)
		{
			div = s;
			s = t % s;
			t = div;
		}

		return div;
	}


	/**
	 * Computes a multiplicative inverse of `x` modulo `n` using the extended
	 * Euclid's algorithm.
	 *
	 * @param x An element for the computation of a multiplicative inverse.
	 * @param n A modulus for the computation of a multiplicative inverse.
	 * @return A multiplicative inverse of `x` modulo `n`.
	 * @throw RsaException if arguments are not valid.
	 */
	static auto inv(const mpz_class &x, const mpz_class &n) -> mpz_class
	{
		if (n <= 0)
		{
			const string err_msg =
				"The parameter `n` of the INV function should be > 0.";
			throw RsaException(err_msg);
		}

		mpz_class g = n, h = x, w = 1, z = 0, v = 0, r = 1, y;
		while (h > 0)
		{
			y = g / h;

			g = g - y * h;
			swap(h, g);

			w = w - y * z;
			swap(z, w);

			v = v - y * r;
			swap(r, v);
		}

		mpz_class inv;
		mpz_mod(inv.get_mpz_t(), v.get_mpz_t(), n.get_mpz_t());

		return inv;
	}


	/**
	 * Computes a Jacobi symbol `a/n`.
	 *
	 * @param a The `a` argument of the Jacobi symbol function.
	 * @param n The `n` argument of the Jacobi symbol function.
	 * @return A Jacobi symbol `a/n`.
	 * @throw RsaException if arguments are not valid.
	 */
	static auto jacobi(const mpz_class &a, const mpz_class &n) -> int
	{
		if (a <= 0 || n <= a || n % 2 == 0)
		{
			const string err_msg =
				"Parameters of the Jacobi symbol function are invalid.";
			throw RsaException(err_msg);
		}

		int t = 1;
		mpz_class _a = a, _n = n, r;
		while (_a != 0)
		{
			while (_a % 2 == 0)
			{
				_a /= 2;
				r = _n % 8;
				if (r == 3 || r == 5)
				{
					t = -t;
				}
			}

			swap(_a, _n);

			if (_a % 4 == 3 && _n % 4 == 3)
			{
				t = -t;
			}

			_a %= _n;
		}

		if (_n == 1)
		{
			return t;
		}

		return 0;
	}


	/**
	 * Checks whether a given number is a prime number using
	 * the Solovay–Strassen test
	 *
	 * @param k A number to be checked whether it is a prime number.
	 * @return True if `k` is likely a prime number, false otherwise.
	 * @throw RsaException if arguments are not valid.
	 */
	auto is_prime(const mpz_class &k) -> bool
	{
		if (k <= 0)
		{
			const string err_msg =
				"The parameter `a` of the `is_prime` function should be > 0.";
			throw RsaException(err_msg);
		}

		if (k == 2 || k == 3)
		{
			return true;
		}
		if (k == 1 || k % 2 == 0)
		{
			return false;
		}

		for (size_t i = 0; i < 100; i++)
		{
			const mpz_class a = 2 + rand.get_z_range(k - 2);

			if (gcd(a, k) > 1)
			{
				return false;
			}

			const mpz_class x = (k + jacobi(a, k)) % k;
			if (x == 0)
			{
				return false;
			}
			mpz_class y;
			mpz_powm(
				y.get_mpz_t(),
				a.get_mpz_t(),
				mpz_class((k - 1) / 2).get_mpz_t(),
				k.get_mpz_t()
			);
			if (x != y)
			{
				return false;
			}
		}

		return true;
	}


	/**
	 * Generates a random prime number of a specified length.
	 *
	 * @param length A length (in bits) of a prime number to be generated.
	 * @return A random prime number of a specified length.
	 * @throw RsaException if arguments are not valid.
	 */
	auto generate_prime(const mp_bitcnt_t length) -> mpz_class
	{
		if (length <= 2)
		{
			const string err_msg =
				"The number of bits of a prime number should be at least 3.";
			throw RsaException(err_msg);
		}

		mpz_class prime = rand.get_z_bits(length);

		const mp_bitcnt_t bts[] = {0, length - 2, length - 1};
		for (const mp_bitcnt_t bt : bts)
		{
			mpz_setbit(prime.get_mpz_t(), bt);
		}

		while (!is_prime(prime))
		{
			prime++++;
		}

		return prime;
	}
};


/**
 * An entry point of the program.
 *
 * @param argc The number of input arguments.
 * @param argv Values of input arguments.
 * @return EXIT_SUCCESS if the RSA algorithm is performed successfully,
 *         EXIT_FAILURE otherwise.
 */
auto main(int argc, char *argv[]) -> int
{
	try
	{
		Rsa rsa(argc, argv);
		rsa.do_operation();
	}
	catch (const RsaException &e)
	{
		cerr << e.what() << endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
