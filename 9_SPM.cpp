#include "examples.h"
#include <ctime>
#include <cstdlib>

//use namespace
using namespace std;
using namespace seal;

void example_SPM()
{
    //print example banner
    print_example_banner("Hamming Distance");
    
    //InitW
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key(   );
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);


    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext vector row size: " << row_size << endl;

    //? Modulus
    auto retrieved_plain_modulus = parms.plain_modulus();
    
    //Make Target String
    //[  0,  1,  1,  0,  0, ...,  0,  0,  1,  1,  0 ]
    vector<uint64_t> T_vector(slot_count, 0ULL);

    //Random Tartget String
    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < slot_count; i++)
    {
        int num = rand();
        T_vector[i] = num % 2;
    }

    cout << "Input Plaintext Target String Vector:" << endl;
    print_matrix(T_vector, row_size);
;
    //plain modulus
    int plain_modulus = 1032193;

    //Encoding 
    for (size_t i = 0; i < slot_count; i++)
    {
        if (T_vector[i] == 0)
            T_vector[i] = plain_modulus - 1;
    }

    vector<long> encode_T_vec(slot_count, 1);

    for (size_t i = 0; i < slot_count; i++)
    {
        if (T_vector[i] > plain_modulus / 2)
            encode_T_vec[i] = (plain_modulus - 1) - plain_modulus;
    }
    cout << "Encoding Target String Vector:" << endl;
    print_matrix(encode_T_vec, row_size);


    Plaintext plain_T_vector;
    print_line(__LINE__);
    cout << "Encode Plaintext Target String Vector" << endl;
    batch_encoder.encode(T_vector, plain_T_vector);

    //Check Decoding
    vector<uint64_t> T_result;
    vector<long> m_T_result(slot_count);
    cout << "   + Decode plaintext vector ...... Correct." << endl;
    batch_encoder.decode(plain_T_vector, T_result);
    for (size_t i = 0; i < slot_count; i++)
    {
        if (T_result[i] == 1)
            m_T_result[i] = T_result[i];
        else if (T_result[i] > plain_modulus / 2)
            m_T_result[i] = T_result[i] - plain_modulus;
    }
    print_matrix(m_T_result, row_size);

    //Encrypt the encoded plaintext.
    Ciphertext encrypted_T_vector;
    print_line(__LINE__);
    cout << "Encrypt plaint Target String vector to encrypted_T_vector." << endl;
    encryptor.encrypt(plain_T_vector, encrypted_T_vector);
    cout << "   + Noise budget in encrypted_T_vector: " << decryptor.invariant_noise_budget(encrypted_T_vector)
         << " bits" << endl; 

    //Make Pattern
    string inputStr;
    cout << "Please enter a pattern : ";
    cin >> inputStr;

    int patternSize = 0; 
    patternSize = inputStr.size();

    vector<uint64_t> P_vector(slot_count, 0ULL);
    int idx = 0;
    for (size_t i = 0; i < slot_count; i++)
    {
        if (idx >= inputStr.size())
            idx = 0;

        P_vector[i] = inputStr[idx] - '0';
        idx++;
    }

    cout << "Input Plaintext Pattern String Vector:" << endl;
    print_matrix(P_vector, row_size);

    //Encoding
    for (size_t i = 0; i < slot_count; i++)
    {
        if (P_vector[i] == 0)
            P_vector[i] = plain_modulus - 1;
    }

    vector<long> encode_P_vec(slot_count, 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        if (P_vector[i] > plain_modulus / 2)
            encode_P_vec[i] = (plain_modulus - 1) - plain_modulus;
    }
    cout << "Encoding Pattern String Vector:" << endl;
    print_matrix(encode_P_vec, row_size);

    Plaintext plain_P_vector;
    print_line(__LINE__);
    batch_encoder.encode(P_vector, plain_P_vector);
    cout << "Encode Plaintext Pattern String Vector" << endl;

    //Calculation
    vector<uint64_t> init_Vector(slot_count, 0ULL);

    for (size_t i = 0; i < init_Vector.size(); i++)
    {
        if (i % patternSize == 0)
            init_Vector[i] = 0;
        else
            init_Vector[i] = 1;
    }

    Plaintext plain_init_vector;
    batch_encoder.encode(init_Vector, plain_init_vector);

    //destination of multiple target string and pattern
    Ciphertext multiple_destination;

    //destination of rotate above multiple value
    Ciphertext rotate_destination;

    //destination of add
    Ciphertext add_destination;

    //destination of result
    Ciphertext result_destination;

    for (size_t i = 0; i < patternSize; i++)
    {
        //T * P
        evaluator.multiply_plain(encrypted_T_vector, plain_P_vector, multiple_destination);

        for (size_t j = 1; j <= patternSize - 1; j++)
        {
            //rot TP
            evaluator.rotate_rows(multiple_destination, i, galois_keys, rotate_destination);

            if (j == 1)
                evaluator.add(multiple_destination, rotate_destination, add_destination);
            else
                evaluator.add_inplace(add_destination, rotate_destination);
        }

        if (i == 0)
        {
            evaluator.multiply_plain(add_destination, plain_init_vector, result_destination);
        }
        else
        {
            evaluator.multiply_plain_inplace(add_destination, plain_init_vector);
            evaluator.rotate_rows_inplace(add_destination, i * -1, galois_keys);

            evaluator.add_inplace(result_destination, add_destination);
        }

        evaluator.rotate_rows_inplace(encrypted_T_vector, 1, galois_keys);
    }  


    //Decrypt
    Plaintext plain_result;
    vector<long> encode_result(slot_count, 1);
    decryptor.decrypt(result_destination, plain_result);
    batch_encoder.decode(plain_result, T_result);
    cout << "   + Result plaintext matrix ...... Correct." << endl;
    for (size_t i = 0; i < slot_count; i++)
    {
        //if (T_result[i] > plain_modulus / 2)
          //  T_result[i] -= plain_modulus;
    }

    print_matrix(T_result, row_size);


    /********************************************************************************
                                  general calculation
    ********************************************************************************/
    print_example_banner("General Calculation");
    vector<long> Target_String(slot_count, 0);
    vector<long> Pattern(slot_count, 0);

    //Copy Target String
    for(size_t i = 0; i < slot_count; i++)
    {
        if (T_vector[i] > 1)
            Target_String[i] = T_vector[i] - plain_modulus;
        else
            Target_String[i] = T_vector[i];
    }
    cout << "Encode Target String" << endl;
    print_matrix(Target_String, row_size);

    print_line(__LINE__);


    //Copy Pattern
    for (size_t i = 0; i < slot_count; i++)
    {
        if (P_vector[i] > 1)
            Pattern[i] = P_vector[i] - plain_modulus;
        else
            Pattern[i] = P_vector[i];
    }
    cout << "Encode Pattern" << endl;
    print_matrix(Pattern, row_size);

    //Inner Product
    print_example_banner("General Calculation - Inner Product");

    vector<long> result(slot_count, 0);

    int referloc = 0;

    //패턴의 크기만큼 반복
    for (size_t k = 0; k < patternSize; k++)
    {
        //복사본의 길이만큼 반복
        for (size_t i = 0; i < slot_count - (patternSize - 1); i++)
        {
            if (i % patternSize == referloc)
            {
                for (size_t j = 0; j < patternSize; j++)
                {
                    //예외 방지
                    if ((i + j) >= slot_count)
                        continue;
                    else
                        result[i] += Target_String[i + j] * Pattern[i + j];    
                }
            }
        }
        referloc++;
        cout << "Result" << referloc << " Vector " << endl;
        print_matrix(result, row_size);

        cout << endl;
        cout << "Rotation Pattern Vector..." << endl;
        
        //Rotation
        int temp = Pattern[slot_count - 1];
        for (size_t i = slot_count - 1; i > 0; i--)
        {
            Pattern[i] = Pattern[i - 1];
        }
        Pattern[0] = temp;
        print_matrix(Pattern, row_size);
    }

    int check_num = 0;
    int correct_num = 0;
    cout << "Please Enter Minimum Number of Pattern Matches: ";
    cin >> correct_num;

    for (size_t i = 0; i < slot_count; i++)
    {
        if (result[i] >= correct_num)
            check_num++;
    }
    cout << endl;
    cout << "Fin Result Vector..." << endl;
    print_matrix(result, row_size);
    // Number of Pattern Matches
    cout << "Number of Pattern Mathches...(Mininum Number of Pattern Matches): " << check_num << endl;
    cout << "Ignore the back " << slot_count % patternSize << "..." << endl;


}   