pub fn english_score(s: &String) -> u32 {
    let mut score = 0;
    for c in s.chars() {
        score += char_freqs(c);
    }

    score
}

//From https://en.wikipedia.org/wiki/Letter_frequency
fn char_freqs(c: char) -> u32 {
    match c {
        'a' => 8167,
        'b' => 1492,
        'c' => 2782,
        'd' => 4253,
        'e' => 12702,
        'f' => 2228,
        'g' => 2015,
        'h' => 6094,
        'i' => 6094,
        'j' => 153,
        'k' => 772,
        'l' => 4025,
        'm' => 2406,
        'n' => 6749,
        'o' => 7507,
        'p' => 1929,
        'q' => 95,
        'r' => 5987,
        's' => 6327,
        't' => 9056,
        'u' => 2758,
        'v' => 978,
        'w' => 2360,
        'x' => 150,
        'y' => 1974,
        'z' => 74,
        ' ' => 13000,
        _ => 0,
    }
}
