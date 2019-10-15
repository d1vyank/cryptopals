#![allow(dead_code, non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

mod aes128;
mod bits;
mod dh;
mod dsa;
mod encoding;
mod hmac;
mod math;
mod mt19937;
mod query_string;
mod rsa;
mod score;
mod sha1;
mod srp;
mod vigenere;
mod xor;

fn main() {
    println!("Run \'cargo test\'");
}

// Set 1 Challenge 1
#[test]
fn hex_to_base64() {
    assert_eq!(encoding::hex_to_base64(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string()
    ).unwrap(), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
}

// Set 1 Challenge 2
#[test]
fn fixed_xor() {
    assert_eq!(
        xor::fixed_xor_hex(
            "1c0111001f010100061a024b53535009181c".to_string(),
            "686974207468652062756c6c277320657965".to_string()
        )
        .unwrap(),
        "746865206b696420646f6e277420706c6179".to_string()
    )
}

// Set 1 Challenge 3
#[test]
fn single_byte_xor_decryption() {
    assert_eq!(
        "Cooking MC\'s like a pound of bacon".to_string(),
        xor::decrypt_single_byte_xor_cipher(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()
        )
        .unwrap()
    );
}

// Set 1 Challenge 4
#[test]
fn single_byte_xor_decryption_from_file() {
    assert_eq!(
        "Now that the party is jumping\n".to_string(),
        xor::find_single_byte_xor_encrypted_string().unwrap()
    );
}

// Set 1 Challenge 5
#[test]
fn repeating_key_xor() {
    assert_eq!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        vigenere::repeating_key_xor(
            "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
                .to_string()
        )
    );
}

// Set 1 Challenge 6
#[test]
fn break_repeating_xor_key() {
    let plaintext_bytes = vigenere::break_repeating_key_xor(
        std::fs::read_to_string("./test_input/set1challenge6.txt").unwrap(),
    )
    .unwrap();
    assert_eq!(
        "Terminator X: Bring the noise".to_string(),
        encoding::ascii_encode(&plaintext_bytes)
    );
}

// Set 1 Challenge 7
#[test]
fn aes_128_ecb_decrypt() {
    let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = base64::decode(
        &std::fs::read_to_string("./test_input/set1challenge7.txt")
            .unwrap()
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let decrypted = aes128::ecb::decrypt(ciphertext.as_slice(), key).unwrap();
    let decrypted_string = std::str::from_utf8(&decrypted).unwrap();

    assert_eq!(plaintext, decrypted_string);

    let encrypted = aes128::ecb::encrypt(plaintext.as_bytes(), key).unwrap();
    assert_eq!(ciphertext, encrypted);
}

// Set 1 Challenge 8
#[test]
fn detect_aes() {
    let content = std::fs::read_to_string("./test_input/set1challenge8.txt").unwrap();

    for (i, line) in content.lines().enumerate() {
        if i == 132 {
            assert!(aes128::ecb::detect(line.as_bytes(), 16));
        } else {
            assert!(!aes128::ecb::detect(line.as_bytes(), 16));
        }
    }
}

// Set 2 Challenge 9
#[test]
fn pkcs7() {
    let mut test = "YELLOW SUBMARINE".to_string().into_bytes();
    encoding::pkcs7_encode(&mut test, 20);
    assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec(), test);

    test = encoding::pkcs7_decode(&test, 20).unwrap();
    assert_eq!("YELLOW SUBMARINE".to_string().into_bytes(), test);

    encoding::pkcs7_encode(&mut test, 16);
    assert_eq!(
        "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
            .as_bytes()
            .to_vec(),
        test
    );

    test = encoding::pkcs7_decode(&test, 16).unwrap();
    assert_eq!("YELLOW SUBMARINE".to_string().into_bytes(), test);
}

// Set 2 Challenge 10
#[test]
fn aes_cbc() {
    let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
    let key = b"YELLOW SUBMARINE";
    let iv: [u8; 16] = [0; 16];
    let ciphertext = base64::decode(
        &std::fs::read_to_string("./test_input/set2challenge10.txt")
            .unwrap()
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let decrypted_bytes = aes128::cbc::decrypt(&ciphertext, key, &iv).unwrap();
    let decrypted_string = std::str::from_utf8(&decrypted_bytes).unwrap();
    assert_eq!(plaintext, decrypted_string);

    let encrypted_bytes = aes128::cbc::encrypt(&decrypted_bytes, key, &iv).unwrap();
    assert_eq!(ciphertext, encrypted_bytes);
}

// Set 2 Challenge 11
#[test]
fn ecb_detection() {
    let mut ecb_count = 0;
    let repeating_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    for _ in 0..50 {
        let mut input: Vec<u8> = (0..2048).map(|_| rand::random::<u8>()).collect();
        input.splice(0..0, repeating_key.iter().cloned());
        input.append(&mut repeating_key.to_vec());
        let out = aes128::encryption_oracle(&input.to_vec()).unwrap();
        if aes128::ecb::detect(&out, 16) {
            ecb_count += 1;
        }
    }

    assert!(ecb_count > 1);
}

// Set 2 Challenge 12
#[test]
fn break_aes_ecb() {
    assert_eq!("Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n",
    aes128::decrypt_aes_ecb_byte_at_a_time());
}

// Set 2 Challenge 13
#[test]
fn ecb_cut_paste() {
    let result = query_string::parse("foo=bar&baz=qux&zap=zazzle".to_string());
    assert_eq!(result.get("foo").unwrap(), "bar");
    assert_eq!(result.get("baz").unwrap(), "qux");
    assert_eq!(result.get("zap").unwrap(), "zazzle");

    assert_eq!(
        query_string::profile_for("foo@bar.com".to_string()),
        "email=foo%40bar.com&uid=10&role=user"
    );

    assert_eq!(
        query_string::profile_for("foo@bar.com&role=admin".to_string()),
        "email=foo%40bar.com%26role%3Dadmin&uid=10&role=user"
    );

    let admin_query_string_ciphertext = query_string::generate_admin_profile();
    let admin_query_string_plaintext =
        query_string::decrypt_profile_oracle(admin_query_string_ciphertext);
    let kv_pairs = query_string::parse(admin_query_string_plaintext);
    assert_eq!(kv_pairs.get("role").unwrap(), "admin");
}

// Set 2 Challenge 14
#[test]
fn break_aes_ecb_padded() {
    assert_eq!("Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n",
    aes128::decrypt_aes_ecb_padded_byte_at_a_time());
}

// Set 2 Challenge 15
#[test]
fn valid_pkcs7() {
    let result = encoding::pkcs7_decode(
        &mut "ICE ICE BABY\x05\x05\x05\x05".to_string().into_bytes(),
        16,
    );
    assert_eq!(result.unwrap_err(), encoding::PKCS7DecodeError);

    let result = encoding::pkcs7_decode(
        &mut "ICE ICE BABY\x01\x02\x03\x04".to_string().into_bytes(),
        16,
    );
    assert_eq!(result.unwrap_err(), encoding::PKCS7DecodeError);
}

// Set 2 Challenge 16

#[test]
fn cbc_bitflipping() {
    assert!(aes128::is_bitflipped_ciphertext_admin(
        aes128::cbc_bitflipping_attack()
    ));
}

// Set 3 Challenge 17
#[test]
fn cbc_oracle_padding() {
    let decrypted_strings = std::fs::read_to_string("./test_input/set3_challenge17.txt").unwrap();

    let plaintext = aes128::cbc_padding_oracle_attack::execute();
    assert!(decrypted_strings.contains(&plaintext));
}

// Set 3 Challenge 18
#[test]
fn ctr_encryption() {
    let key = b"YELLOW SUBMARINE";
    let nonce = 0;

    let plaintext = "testing a very very very loooooooooong string";
    let ciphertext = aes128::ctr::encrypt(plaintext.as_bytes(), key, nonce).unwrap();
    let decrypted = aes128::ctr::decrypt(&ciphertext, key, nonce).unwrap();
    assert_eq!(plaintext, encoding::ascii_encode(&decrypted));

    let plaintext_bytes = aes128::ctr::decrypt(
        &base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap(),
        key,
        nonce,
    )
    .unwrap();

    assert_eq!(
        "Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ".to_string(),
        encoding::ascii_encode(&plaintext_bytes)
    );
}

// Set 3 Challenge 20
#[test]
fn break_fixed_nonce_ctr() {
    let contents = std::fs::read_to_string("./test_input/set3_challenge20.txt").unwrap();
    let mut ciphertexts = vec![];
    let mut plaintexts = vec![];
    for line in contents.lines() {
        ciphertexts.push(aes128::ctr::encrypt_fixed_nonce_key(
            &base64::decode(line).unwrap(),
        ));
    }
    let keystream = aes128::attack_fixed_nonce_ctr_ciphertexts(ciphertexts.clone());

    for ciphertext in ciphertexts.iter() {
        let plaintext: String = ciphertext
            .iter()
            .zip(keystream.iter().cycle())
            .map(|(x, y)| (x ^ y) as char)
            .collect();
        plaintexts.push(plaintext);
    }

    assert_eq!(
        "I\'m rated \"R\"...this is a warning, ya better void / Poets are paranoid, DJ\'s D-stroyedCuz I came back to attack others in spite- / Strike like lightnin\', It\'s quite frightenin\'!But don\'t be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a spark;Ya tremble like a alcoholic, muscles tighten up / What\'s that, lighten up! You see a sight butSuddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quick!Music\'s the clue, when I come your warned / Apocalypse Now, when I\'m done, ya gone!Haven\'t you ever heard of a MC-murderer? / This is the death penalty,and I\'m servin\' aDeath wish, so come on, step to this / Hysterical idea for a lyrical professionist!Friday the thirteenth, walking down Elm Street / You come in my realm ya get beat!This is off limits, so your visions are blurry / All ya see is the meters at a volumeTerror in the styles, never error-files / Indeed I\'m known-your exiled!For those that oppose to be level or next to this / I ain\'t a devil and this ain\'t the Exorcist!Worse than a nightmare, you don\'t have to sleep a wink / The pain\'s a migraine every time ya thinkFlashbacks interfere, ya start to hear: / The R-A-K-I-M in your ear;Then the beat is hysterical / That makes Eric go get a ax and chops the wackSoon the lyrical format is superior / Faces of death remainMC\'s decaying, cuz they never stayed / The scene of a crime every night at the showThe fiend of a rhyme on the mic that you know / It\'s only one capable, breaks-the unbreakableMelodies-unmakable, pattern-unescapable / A horn if want the style I possesI bless the child, the earth, the gods and bomb the rest / For those that envy a MC it can beHazardous to your health so be friendly / A matter of life and death, just like a etch-a-sketchShake \'till your clear, make it disappear, make the next / After the ceremony, let the rhyme rest in eeactIf not, my soul\'ll release! / The scene is recreated, reincarnated, updated, I\'m glad you made itCuz your about to see a disastrous sight / A performance never again performed on a mic:Lyrics of fury! A fearified freestyle! / The \"R\" is in the house-too much tension!Make sure the system\'s loud when I mention / Phrases that\'s fearsomeYou want to hear some sounds that not only pounds but please your eardrums; / I sit back and observe ahe fhoa  >innh  Then nonchalantly tell you what it mean to me / Strictly business I\'m quickly in this moodAnd I don\'t care if the whole crowd\'s a witness! / I\'m a tear you apart but I\'m a spare you a heartProgram into the speed of the rhyme, prepare to start / Rhythm\'s out of the radius, insane as the craoieseMusical madness MC ever made, see it\'s / Now an emergency, open-heart surgeryOpen your mind, you will find every word\'ll be / Furier than ever, I remain the furtureBattle\'s tempting...whatever suits ya! / For words the sentence, there\'s no resemblanceYou think you\'re ruffer, then suffer the consequences! / I\'m never dying-terrifying resultsI wake ya with hundreds of thousands of volts / Mic-to-mouth resuscitation, rhythm with radiationNovocain ease the pain it might save him / If not, Eric B.\'s the judge, the crowd\'s the juryYo Rakim, what\'s up? / Yo, I\'m doing the knowledge, E., man I\'m trying to get paid in fullWell, check this out, since Norby Walters is our agency, right? / TrueKara Lewis is our agent, word up / Zakia and 4th and Broadway is our record company, indeedOkay, so who we rollin\' with then? We rollin\' with Rush / Of Rushtown ManagementCheck this out, since we talking over / This def beat right here that I put togetherI wanna hear some of them def rhymes, you know what I\'m sayin\'? / And together, we can get paid in fuylThinkin\' of a master plan / \'Cuz ain\'t nuthin\' but sweat inside my handSo I dig into my pocket, all my money is spent / So I dig deeper but still comin\' up with lintSo I start my mission, leave my residence / Thinkin\' how could I get some dead presidentsI need money, I used to be a stick-up kid / So I think of all the devious things I didI used to roll up, this is a hold up, ain\'t nuthin\' funny / Stop smiling, be still, don\'t nuthin\' movp bue te   eeetBut now I learned to earn \'cuz I\'m righteous / I feel great, so maybe I might justSearch for a nine to five, if I strive / Then maybe I\'ll stay aliveSo I walk up the street whistlin\' this / Feelin\' out of place \'cuz, man, do I missA pen and a paper, a stereo, a tape of / Me and Eric B, and a nice big plate ofFish, which is my favorite dish / But without no money it\'s still a wish\'Cuz I don\'t like to dream about gettin\' paid / So I dig into the books of the rhymes that I madeSo now to test to see if I got pull / Hit the studio, \'cuz I\'m paid in fullRakim, check this out, yo / You go to your girl house and I\'ll go to mine\'Cause my girl is definitely mad / \'Cause it took us too long to do this albumYo, I hear what you\'re saying / So let\'s just pump the music upAnd count our money / Yo, well check this out, yo EliTurn down the bass down / And let the beat just keep on rockin\'And we outta here / Yo, what happened to peace? / Peace".to_string(),
        plaintexts
            .iter()
            .map(|s| s.chars())
            .flatten()
            .collect::<String>()
    );
}

// Set 3 Challenge 21
#[test]
fn mt19937_gen() {
    let mut rng = mt19937::MersenneRng::new(12346);
    let n1 = rng.extract_number();
    let n2 = rng.extract_number();
    let n3 = rng.extract_number();

    assert_ne!(n1, n2);
    assert_ne!(n1, n3);
    assert_ne!(n2, n3);

    let mut rng2 = mt19937::MersenneRng::new(12346);
    let m1 = rng2.extract_number();
    let m2 = rng2.extract_number();
    let m3 = rng2.extract_number();

    assert_eq!(n1, m1);
    assert_eq!(n2, m2);
    assert_eq!(n3, m3);
}

// Set 3 Challenge 22
#[test]
fn guess_mt19937_seed() {
    let (first_random_number, seed) = mt19937::timestamp_seeded_rng_oracle();
    let guessed_seed = mt19937::guess_unix_timestamp_seed(first_random_number);
    assert_eq!(seed, guessed_seed);
}

// Set 3 Challenge 23
#[test]
fn clone_mt19937() {
    let mut rng = mt19937::MersenneRng::new(123456);
    let mut samples = vec![];

    // collect N=624 samples
    for _ in 0..624 {
        samples.push(rng.extract_number());
    }

    let mut rng_clone = mt19937::MersenneRng::clone(samples);

    // assert clone produces same values as original
    for _ in 0..1000 {
        assert_eq!(rng.extract_number(), rng_clone.extract_number());
    }
}

// Set 3 Challenge 24
#[test]
// skip slow brute force test
#[ignore]
fn brute_force_mt19937_cipher() {
    let key = 43210;
    assert_eq!(key, mt19937::break_mt_cipher());

    assert!(mt19937::detect_timestamp_seeded_token());
}

// Set 4 Challenge 25
#[test]
fn break_aes_ctr_random_rw() {
    let plaintext = std::fs::read("./test_input/set4_challenge25.txt").unwrap();
    assert_eq!(plaintext, aes128::break_random_access_rw_ctr())
}

// Set 4 Challenge 26
#[test]
fn ctr_bitflipping() {
    let chosen_ciphertext = aes128::ctr_bitflipping_attack();
    assert_eq!(
        true,
        aes128::is_bitflipped_ctr_ciphertext_admin(&chosen_ciphertext)
    );
}

// Set 4 Challenge 27
#[test]
fn find_cbc_key_when_iv_equals_key() {
    assert_eq!(
        aes128::insecure_cbc_iv_attack::constant_key().to_vec(),
        aes128::insecure_cbc_iv_attack::execute()
    )
}

// Set 4 Challenge 28
#[test]
fn sha1_keyed_mac() {
    let mac1 = sha1::keyed_mac(b"YELLOW SUBMARINE", b"HELLO WORLD");
    let mac2 = sha1::keyed_mac(b"YELLOW SUBMARINE", b"HELLO MARS");
    assert_ne!(mac1, mac2);

    let mac3 = sha1::keyed_mac(b"ORANGE SUBMARINE", b"HELLO WORLD");
    assert_ne!(mac1, mac3);
}

// Set 4 Challenge 29
#[test]
fn sha1_length_extension_attack() {
    let (message, mac) = sha1::length_extension_attack::execute();
    assert!(sha1::length_extension_attack::is_admin(&message, &mac));
}

// Set 4 Challenge 31 and 32
#[test]
// Ignore slow test
#[ignore]
fn hmac_timing_attack() {
    assert_eq!(
        hmac::timing_attack_1::execute("foo".to_string()),
        "dea3f511e5baa6b483da601a5ad43b03d9cbb4cf"
    )
}

// Set 5 Challenge 33
#[test]
fn diffie_hellman() {
    let alice_secret = dh::ephemeral_secret();
    let bob_secret = dh::ephemeral_secret();

    let alice_pub_key = dh::public_key(&dh::chosen_prime(), &dh::primitive_root(), &alice_secret);
    let bob_pub_key = dh::public_key(&dh::chosen_prime(), &dh::primitive_root(), &bob_secret);

    let alice_shared_secret = alice_secret.diffie_hellman(&bob_pub_key);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_pub_key);

    assert_eq!(alice_shared_secret, bob_shared_secret);
}

// Set 5 Challenge 34
#[test]
fn diffie_hellman_mitm_pk() {
    dh::mitm::malicious_public_key();
}

// Set 5 Challenge 35
#[test]
fn diffie_hellman_mitm_g() {
    dh::mitm::malicious_primitive_root();
}

// Set 5 Challenge 36
#[test]
fn secure_remote_password() {
    let mut s = srp::Server::new(
        123321,
        "test@example.com".to_string(),
        "password".to_string(),
    );
    let c = srp::Client::new(
        123321,
        "test@example.com".to_string(),
        "password".to_string(),
    );

    let (I, A) = c.initiate_handshake();
    let (salt, server_public_key) = s.accept_handshake(I, &A);
    let hashed_key = c.complete_handshake(salt, &server_public_key);
    s.complete_handshake(&hashed_key);
}

// Set 5 Challenge 37
#[test]
fn zero_key_srp_attack() {
    use num_traits::cast::FromPrimitive;

    let mut s = srp::Server::new(
        123321,
        "test@example.com".to_string(),
        "password".to_string(),
    );
    let c = srp::ZeroKeyClient::new(
        num_bigint::BigUint::from_u64(0).unwrap(),
        "test@example.com".to_string(),
    );

    let (I, A) = c.initiate_handshake();
    let (salt, server_public_key) = s.accept_handshake(I, &A);
    let hashed_key = c.complete_handshake(salt, &server_public_key);
    assert!(s.complete_handshake(&hashed_key));
}

// Set 5 Challenge 38
#[test]
fn simplified_srp_dict_attack() {
    let mut s = srp::SimpleServer::new("test@example.com".to_string(), "password".to_string());
    let c = srp::SimpleClient::new("test@example.com".to_string(), "password".to_string());

    // assert handshake works with a valid client, server
    let (email, client_public_key) = c.initiate_handshake();
    let (salt, server_public_key, large_random_number) =
        s.accept_handshake(email, &client_public_key);
    let hashed_key = c.complete_handshake(salt, &server_public_key, &large_random_number);
    assert!(s.complete_handshake(&hashed_key));

    // test MITM attack on client
    let chosen_weak_password = "password".to_string();
    let c = srp::SimpleClient::new("test@example.com".to_string(), chosen_weak_password.clone());
    let cracked_password = srp::simple_srp_offline_dict_mitm(
        &c,
        std::fs::read_to_string("./test_input/password_dictonary.txt")
            .unwrap()
            .lines(),
    );
    assert_eq!(chosen_weak_password, cracked_password);
}

// Set 5 Challenge 39
#[test]
fn rsa() {
    let plaintext = "BIG YELLOW SUBMARINE";
    let r = rsa::RSA::new(2048);
    let ciphertext = r.encrypt(plaintext.as_bytes());
    let decrypted = r.decrypt(&ciphertext);

    assert_eq!(plaintext, encoding::ascii_encode(&decrypted));
}

// Set 5 Challenge 40
#[test]
fn rsa_broadcast_attack() {
    assert!(rsa::broadcast_attack());
}

// Set 6 Challenge 41
#[test]
fn rsa_unpadded_message_recovery() {
    use num_bigint::BigUint;

    let plaintext = "BIG YELLOW SUBMARINE";
    let s = rsa::VulnerableServer::new();
    let (e, N) = s.public_key();
    let c = BigUint::from_bytes_be(plaintext.as_bytes()).modpow(&e, &N);
    let recovered_plaintext = rsa::recover_unpadded_message(s, &c.to_bytes_be());

    assert_eq!(plaintext, encoding::ascii_encode(&recovered_plaintext))
}

// Set 6 Challenge 42
#[test]
fn rsa_signature_forgery() {
    let plaintext = "BIG YELLOW SUBMARINE";
    let r = rsa::RSA::new(2048);

    let signature = r.sign(plaintext.as_bytes());
    let verified_plaintext = r.verify(&signature);
    assert_eq!(plaintext, encoding::ascii_encode(&verified_plaintext));

    let plaintext = "hi mom";
    let forged_signature = rsa::forge_rsa_signature(plaintext.to_string());
    assert_eq!(
        plaintext,
        encoding::ascii_encode(&r.verify(&forged_signature)),
    )
}

// Set 6 Challenge 43
#[test]
// Ignore slow nonce bruteforce
#[ignore]
fn dsa_key_recovery() {
    use num_bigint::{BigInt, BigUint};
    let message = format!(
        "For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch\n"
    );

    assert_eq!(
        hex::encode(sha1::hash(message.as_bytes())),
        "d2d0714f014a9784047eaeccf956520045c45265"
    );

    let pub_key = BigUint::parse_bytes("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17".as_bytes(), 16).unwrap();
    let r =
        BigUint::from_bytes_be(&hex::decode("60019CACDC56EEDF8E080984BFA898C8C5C419A8").unwrap());
    let s =
        BigUint::from_bytes_be(&hex::decode("961F2062EFC3C68DB965A90C924CF76580EC1BBC").unwrap());

    let v = dsa::DSA::new_verifier(pub_key.clone());
    assert!(v.verify(message.as_bytes(), (r.clone(), s.clone())));

    let key = dsa::recover_private_key_weak_nonce(
        message,
        (BigInt::from(r), BigInt::from(s)),
        BigInt::from(pub_key),
    );
    assert_eq!(
        hex::decode("0954edd5e0afe5542a4adf012611a91912a3ec16").unwrap(),
        sha1::hash(hex::encode(&key.to_bytes_be().1).as_bytes())
    )
}

// Set 6 Challenge 44
#[test]
fn dsa_key_recovery2() {
    use num_bigint::{BigInt, Sign};

    let pub_key = BigInt::parse_bytes("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821".as_bytes(), 16).unwrap();

    let r = BigInt::from_bytes_be(
        Sign::Plus,
        &hex::decode("281CAB682EA0C19C68AFB59F858338D3AA635CC5").unwrap(),
    );

    let m1 = BigInt::from_bytes_be(
        Sign::Plus,
        &hex::decode("21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4").unwrap(),
    );
    let s1 = BigInt::from_bytes_be(
        Sign::Plus,
        &hex::decode("30AFE50E59BDBD5E0D46E34C141BD964B93C7CDB").unwrap(),
    );
    let m2 = BigInt::from_bytes_be(
        Sign::Plus,
        &hex::decode("d6340bfcda59b6b75b59ca634813d572de800e8f").unwrap(),
    );
    let s2 = BigInt::from_bytes_be(
        Sign::Plus,
        &hex::decode("504CAB8BC826DCCC289D18070ADCE2EAA31D244F").unwrap(),
    );

    let key = dsa::recover_private_key_repeated_nonce(pub_key, s1, s2, m1, m2, r);
    assert_eq!(
        hex::decode("ca8f6f7c66fa362d40760d135b763eb8527d3d52").unwrap(),
        sha1::hash(hex::encode(&key.to_bytes_be().1).as_bytes())
    )
}

// Set 6 Challenge 45
#[test]
fn dsa_parameter_tampering() {
    use num_bigint::BigUint;
    use num_traits::identities::Zero;

    // g = 0
    let message = "Big Yellow Submarine";
    let another_message = "Any other string";
    let d = dsa::DSA::new(Some(BigUint::zero()));
    let signature = d.sign(message.as_bytes());
    assert!(d.verify(message.as_bytes(), signature.clone()));
    assert!(d.verify(another_message.as_bytes(), signature));

    // g = p + 1
    let d = dsa::DSA::new(Some(dsa::p() + 1u8));
    let magic_signature = dsa::magic_signature(&d.public_key);
    assert!(d.verify("Hello, world".as_bytes(), magic_signature.clone()));
    assert!(d.verify("Goodbye, world".as_bytes(), magic_signature));
}

// Set 6 Challenge 46
#[ignore]
#[test]
fn rsa_parity_oracle() {
    let plaintext = base64::decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==").unwrap();

    let r = rsa::RSA::new(2048);
    let ciphertext = r.encrypt(&plaintext);
    let decrypted = rsa::parity_oracle_attack(&ciphertext, r.public_key.clone(), r);

    assert_eq!(plaintext, decrypted);
}

// Set 6 Challenge 47
#[test]
fn rsa_padding_oracle_attack() {
    rsa::pkcs_padding_oracle_attack(256);
}

// Set 6 Challenge 48
#[test]
fn rsa_padding_oracle_attack2() {
    rsa::pkcs_padding_oracle_attack(768);
}
