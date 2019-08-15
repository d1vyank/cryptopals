#![allow(dead_code, unused_imports)]

use rand::Rng;
use std::{fs, str};

mod aes128;
mod bits;
mod encoding;
mod mt19937;
mod query_string;
mod score;
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
    assert_eq!(
        "Terminator X: Bring the noise".to_string(),
        vigenere::break_repeating_key_xor(
            fs::read_to_string("./test_input/set1challenge6.txt").unwrap()
        )
        .unwrap()
        .iter()
        .map(|v| v.clone() as char)
        .collect::<String>()
    );
}

// Set 1 Challenge 7
#[test]
fn aes_128_ecb_decrypt() {
    let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = base64::decode(
        &fs::read_to_string("./test_input/set1challenge7.txt")
            .unwrap()
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let decrypted = aes128::ecb::decrypt(ciphertext.as_slice(), key).unwrap();
    let decrypted_string = str::from_utf8(&decrypted).unwrap();

    assert_eq!(plaintext, decrypted_string);

    let encrypted = aes128::ecb::encrypt(plaintext.as_bytes(), key).unwrap();
    assert_eq!(ciphertext, encrypted);
}

// Set 1 Challenge 8
#[test]
fn detect_aes() {
    let content = fs::read_to_string("./test_input/set1challenge8.txt").unwrap();

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
        &fs::read_to_string("./test_input/set2challenge10.txt")
            .unwrap()
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let decrypted_bytes = aes128::cbc::decrypt(&ciphertext, key, &iv).unwrap();
    let decrypted_string = str::from_utf8(&decrypted_bytes).unwrap();
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
    let decrypted_strings = fs::read_to_string("./test_input/set3_challenge17.txt").unwrap();

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
    assert_eq!(
        plaintext,
        decrypted
            .iter()
            .map(|v| v.clone() as char)
            .collect::<String>()
    );

    let plaintext_bytes = aes128::ctr::decrypt(
        &base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap(),
        key,
        nonce,
    )
    .unwrap();

    let plaintext: String = plaintext_bytes.iter().map(|v| v.clone() as char).collect();
    assert_eq!(
        "Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ".to_string(),
        plaintext
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
// skip slow brute force test
//#[test]
fn break_mt19937_cipher() {
    let key = 43210;
    assert_eq!(key, mt19937::break_mt_cipher());

    assert!(mt19937::detect_timestamp_seeded_token());
}
