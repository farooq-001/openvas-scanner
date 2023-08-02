// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod helper;
#[cfg(test)]
mod tests {
    use nasl_interpreter::*;

    #[test]
    fn aes_mac_gcm() {
        let code = r###"
        key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");
        data = hexstr_to_data("d5de42b461646c255c87bd2962d3b9a2");
        iv = hexstr_to_data("ee283a3fc75575e33efd4887");
        crypt = aes_mac_gcm(key: key, data: data, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert!(parser.next().unwrap().is_ok());
    }
}
