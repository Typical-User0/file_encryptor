pub fn get_encrypted_filename(filename: &str) -> String {
    let vec: Vec<&str> = filename.split('.').collect();
    let mut base_name = String::from(*vec.get(0).unwrap_or(&filename));

    if let Some(&"enc") = vec.get(1) {
        base_name.push('1');
    }

    base_name.push_str(".enc");
    base_name
}

#[cfg(test)]
mod tests {
    use crate::utils::get_encrypted_filename;

    #[test]
    fn test_txt_file() {
        let filename = "input.txt";
        assert_eq!(get_encrypted_filename(filename), "input.enc")
    }

    #[test]
    fn test_no_extension_file() {
        let filename = "input";
        assert_eq!(get_encrypted_filename(filename), "input.enc")
    }

    #[test]
    fn test_enc_file() {
        let filename = "input.enc";
        assert_eq!(get_encrypted_filename(filename), "input1.enc")
    }
}
