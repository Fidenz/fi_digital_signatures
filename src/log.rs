#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(value: &str);
    #[wasm_bindgen(js_namespace = console)]
    pub fn error(value: &str);
}

#[cfg(not(feature = "wasm"))]
#[allow(dead_code)]
pub fn log(value: &str) {
    println!("{}", value);
}
#[cfg(not(feature = "wasm"))]
pub fn error(value: &str) {
    eprintln!("{}", value);
}
