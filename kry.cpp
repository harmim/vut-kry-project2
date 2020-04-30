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
		if (argc < 2 || strlen(argv[1]) != 2 || argv[1][0] != '-')
		{
			throw RsaException(INVALID_ARGS_MSG);
		}

		string err_msg;
		switch (static_cast<Operation>(argv[1][1]))
		{
			case Operation::GENERATE:
				if (argc != 3)
				{
					throw RsaException(INVALID_ARGS_MSG);
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
				if (argc != 5)
				{
					throw RsaException(INVALID_ARGS_MSG);
				}

				err_msg =
					"Error: the arguments E, N, M should be hexadecimal numbers"
					" (prefix 0x or 0X).";
				if (!is_hex(argv[2]) || !is_hex(argv[3]) || !is_hex(argv[4]))
				{
					throw RsaException(err_msg);
				}
				try
				{
					e = mpz_class(argv[2]);
					n = mpz_class(argv[3]);
					m = mpz_class(argv[4]);
				}
				catch (const exception &e)
				{
					throw RsaException(err_msg);
				}

				operation = Operation::ENCRYPT;
				break;

			case Operation::DECRYPT:
				if (argc != 5)
				{
					throw RsaException(INVALID_ARGS_MSG);
				}

				err_msg =
					"Error: the arguments D, N, C should be hexadecimal numbers"
					" (prefix 0x or 0X).";
				if (!is_hex(argv[2]) || !is_hex(argv[3]) || !is_hex(argv[4]))
				{
					throw RsaException(err_msg);
				}
				try
				{
					d = mpz_class(argv[2]);
					n = mpz_class(argv[3]);
					c = mpz_class(argv[4]);
				}
				catch (const exception &e)
				{
					throw RsaException(err_msg);
				}

				operation = Operation::DECRYPT;
				break;

			case Operation::BREAK:
				if (argc != 5)
				{
					throw RsaException(INVALID_ARGS_MSG);
				}

				err_msg =
					"Error: the arguments E, N, C should be hexadecimal numbers"
					" (prefix 0x or 0X).";
				if (!is_hex(argv[2]) || !is_hex(argv[3]) || !is_hex(argv[4]))
				{
					throw RsaException(err_msg);
				}
				try
				{
					e = mpz_class(argv[2]);
					n = mpz_class(argv[3]);
					c = mpz_class(argv[4]);
				}
				catch (const exception &e)
				{
					throw RsaException(err_msg);
				}

				operation = Operation::BREAK;
				break;

			default:
				throw RsaException(INVALID_ARGS_MSG);
		}
	}


	/**
	 * Performs a specified RSA operation.
	 */
	auto do_operation() -> void
	{
		switch (operation)
		{
			case Operation::GENERATE:
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
				break;
		}
	}


private:
	/**
	 * Possible operations to be performed.
	 */
	enum class Operation : const
	char
	{
		GENERATE = 'g', /// generation of keys
			ENCRYPT = 'e', /// encryption
			DECRYPT = 'd', /// decryption
			BREAK = 'b', /// breaking the RSA
	};


	/// An error message for invalid input arguments.
	const string INVALID_ARGS_MSG =
		"Error: invalid arguments."
		" Expecting: -g B | -e E N M | -d D N C | -b E N C";


	Operation operation; /// An operation to be performed.
	unsigned long b = 0; /// A required size of a public modulus.
	mpz_class p; /// The first prime number.
	mpz_class q; /// The second prime number.
	mpz_class n; /// A public modulus.
	mpz_class e; /// A public exponent.
	mpz_class d; /// A private exponent.
	mpz_class m; /// A decrypted message.
	mpz_class c; /// An encrypted message.


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
