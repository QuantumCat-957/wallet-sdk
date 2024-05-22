#[derive(Debug)]
pub enum Language {
    English,
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    French,
    Italian,
    Japanese,
    Korean,
    Portuguese,
    Spanish,
}

impl Language {
    pub fn from_str(lang: &str) -> Result<Self, anyhow::Error> {
        Ok(match lang {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            "czech" => Language::Czech,
            "french" => Language::French,
            "italian" => Language::Italian,
            "japanese" => Language::Japanese,
            "korean" => Language::Korean,
            "portuguese" => Language::Portuguese,
            "spanish" => Language::Spanish,
            _ => return Err(anyhow::anyhow!("Unknown lang")),
        })
    }
}

#[derive(Debug, Clone)]
pub enum WordlistWrapper {
    English(coins_bip39::English),
    ChineseSimplified(coins_bip39::ChineseSimplified),
    ChineseTraditional(coins_bip39::ChineseTraditional),
    Czech(coins_bip39::Czech),
    French(coins_bip39::French),
    Italian(coins_bip39::Italian),
    Japanese(coins_bip39::Japanese),
    Korean(coins_bip39::Korean),
    Portuguese(coins_bip39::Portuguese),
    Spanish(coins_bip39::Spanish),
}

impl WordlistWrapper {
    pub fn new(lang: &str) -> Result<WordlistWrapper, anyhow::Error> {
        let language = Language::from_str(lang)?;
        Ok(language.to_wordlist_wrapper())
    }
}

impl Language {
    pub fn to_wordlist_wrapper(self) -> WordlistWrapper {
        match self {
            Language::English => WordlistWrapper::English(coins_bip39::English),
            Language::ChineseSimplified => {
                WordlistWrapper::ChineseSimplified(coins_bip39::ChineseSimplified)
            }
            Language::ChineseTraditional => {
                WordlistWrapper::ChineseTraditional(coins_bip39::ChineseTraditional)
            }
            Language::Czech => WordlistWrapper::Czech(coins_bip39::Czech),
            Language::French => WordlistWrapper::French(coins_bip39::French),
            Language::Italian => WordlistWrapper::Italian(coins_bip39::Italian),
            Language::Japanese => WordlistWrapper::Japanese(coins_bip39::Japanese),
            Language::Korean => WordlistWrapper::Korean(coins_bip39::Korean),
            Language::Portuguese => WordlistWrapper::Portuguese(coins_bip39::Portuguese),
            Language::Spanish => WordlistWrapper::Spanish(coins_bip39::Spanish),
        }
    }

    pub fn gen_phrase(self, count: usize) -> Result<Vec<String>, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let phrase =
            match self {
                Language::English => {
                    coins_bip39::Mnemonic::<coins_bip39::English>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
                Language::ChineseSimplified => coins_bip39::Mnemonic::<
                    coins_bip39::ChineseSimplified,
                >::new_with_count(&mut rng, count)?
                .to_phrase(),
                Language::ChineseTraditional => coins_bip39::Mnemonic::<
                    coins_bip39::ChineseTraditional,
                >::new_with_count(&mut rng, count)?
                .to_phrase(),
                Language::Czech => {
                    coins_bip39::Mnemonic::<coins_bip39::Czech>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
                Language::French => {
                    coins_bip39::Mnemonic::<coins_bip39::French>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
                Language::Italian => {
                    coins_bip39::Mnemonic::<coins_bip39::Italian>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
                Language::Japanese => {
                    coins_bip39::Mnemonic::<coins_bip39::Japanese>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
                Language::Korean => {
                    coins_bip39::Mnemonic::<coins_bip39::Korean>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
                Language::Portuguese => {
                    coins_bip39::Mnemonic::<coins_bip39::Portuguese>::new_with_count(
                        &mut rng, count,
                    )?
                    .to_phrase()
                }
                Language::Spanish => {
                    coins_bip39::Mnemonic::<coins_bip39::Spanish>::new_with_count(&mut rng, count)?
                        .to_phrase()
                }
            };
        let words = phrase
            .split(' ')
            .into_iter()
            .map(|word| word.to_string())
            .collect();
        Ok(words)
    }
}
