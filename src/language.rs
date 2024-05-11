use serde::{Deserialize, Serialize};

use crate::keystore::Keystore;

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

#[derive(Debug, Clone)]
pub struct Word<W> {
    _wordlist: std::marker::PhantomData<W>,
}

impl<W: coins_bip39::Wordlist + Clone> Word<W> {
    pub fn gen_phrase() -> String {
        let mut rng = rand::thread_rng();
        let mnemonic = coins_bip39::Mnemonic::<W>::new(&mut rng);
        mnemonic.to_phrase()
    }
}

impl<W: coins_bip39::Wordlist + Clone> Word<W> {
    pub fn new() -> Self {
        Self {
            _wordlist: std::marker::PhantomData,
        }
    }
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
    // pub fn to_word(self) -> std::ptr::NonNull<()> {
    //     match self {
    //         Language::English => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::English,
    //             >::new())))
    //             .cast()
    //         },
    //         Language::ChineseSimplified => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::ChineseSimplified,
    //             >::new())))
    //             .cast()
    //         },
    //         Language::ChineseTraditional => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::ChineseTraditional,
    //             >::new())))
    //             .cast()
    //         },
    //         Language::Czech => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(
    //                 Word::<coins_bip39::Czech>::new(),
    //             )))
    //             .cast()
    //         },
    //         Language::French => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(
    //                 Word::<coins_bip39::French>::new(),
    //             )))
    //             .cast()
    //         },
    //         Language::Italian => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::Italian,
    //             >::new())))
    //             .cast()
    //         },
    //         Language::Japanese => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::Japanese,
    //             >::new())))
    //             .cast()
    //         },
    //         Language::Korean => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(
    //                 Word::<coins_bip39::Korean>::new(),
    //             )))
    //             .cast()
    //         },
    //         Language::Portuguese => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::Portuguese,
    //             >::new())))
    //             .cast()
    //         },
    //         Language::Spanish => unsafe {
    //             std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(Word::<
    //                 coins_bip39::Spanish,
    //             >::new())))
    //             .cast()
    //         },
    //     }
    // }
}

// impl<W: coins_bip39::Wordlist + Clone> From<Language> for Word<W> {
//     fn from(value: Language) -> Self {
//         match value {
//             Language::English => Word::<W>::new(),
//             Language::ChineseSimplified => Word::<W>::new(),
//             Language::ChineseTraditional => Word::<W>::new(),
//             Language::Czech => Word::<W>::new(),
//             Language::French => Word::<W>::new(),
//             Language::Italian => Word::<W>::new(),
//             Language::Japanese => Word::<W>::new(),
//             Language::Korean => Word::<W>::new(),
//             Language::Portuguese => Word::<W>::new(),
//             Language::Spanish => Word::<W>::new(),
//             Language::Unknown => Word::<W>::new(),
//         }
//     }
// }

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

    pub fn gen_phrase(self) -> String {
        let mut rng = rand::thread_rng();
        match self {
            Language::English => {
                coins_bip39::Mnemonic::<coins_bip39::English>::new(&mut rng).to_phrase()
            }
            Language::ChineseSimplified => {
                coins_bip39::Mnemonic::<coins_bip39::ChineseSimplified>::new(&mut rng).to_phrase()
            }
            Language::ChineseTraditional => {
                coins_bip39::Mnemonic::<coins_bip39::ChineseTraditional>::new(&mut rng).to_phrase()
            }
            Language::Czech => {
                coins_bip39::Mnemonic::<coins_bip39::Czech>::new(&mut rng).to_phrase()
            }
            Language::French => {
                coins_bip39::Mnemonic::<coins_bip39::French>::new(&mut rng).to_phrase()
            }
            Language::Italian => {
                coins_bip39::Mnemonic::<coins_bip39::Italian>::new(&mut rng).to_phrase()
            }
            Language::Japanese => {
                coins_bip39::Mnemonic::<coins_bip39::Japanese>::new(&mut rng).to_phrase()
            }
            Language::Korean => {
                coins_bip39::Mnemonic::<coins_bip39::Korean>::new(&mut rng).to_phrase()
            }
            Language::Portuguese => {
                coins_bip39::Mnemonic::<coins_bip39::Portuguese>::new(&mut rng).to_phrase()
            }
            Language::Spanish => {
                coins_bip39::Mnemonic::<coins_bip39::Spanish>::new(&mut rng).to_phrase()
            }
        }
    }
}

// impl<W: coins_bip39::Wordlist + Clone> From<Language> for Keystore<W> {
//     fn from(value: Language) -> Self {
//         match value {
//             Language::English => Keystore::<W>::new(),
//             Language::ChineseSimplified => Keystore::<W>::new(),
//             Language::ChineseTraditional => Keystore::<W>::new(),
//             Language::Czech => Keystore::<W>::new(),
//             Language::French => Keystore::<W>::new(),
//             Language::Italian => Keystore::<W>::new(),
//             Language::Japanese => Keystore::<W>::new(),
//             Language::Korean => Keystore::<W>::new(),
//             Language::Portuguese => Keystore::<W>::new(),
//             Language::Spanish => Keystore::<W>::new(),
//         }
//     }
// }
