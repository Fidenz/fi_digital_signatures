#[cfg(feature = "wasm")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(js_namespace = console)]
    pub fn log();
    #[wasm_bindgen::prelude::wasm_bindgen(js_namespace = console)]
    pub fn error();
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
