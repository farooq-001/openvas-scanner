#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nasl_interpreter::{Storage, Interpreter, ContextType, NaslValue, error::InterpretError};
    use nasl_syntax::parse;

    struct MockStorage {
        map: HashMap<String, String>,
    }

    impl MockStorage {
        fn new() -> Self {
            MockStorage {
                map: HashMap::new(),
            }
        }
    }
    impl Storage for MockStorage {
        fn write(&mut self, key: &str, value: &str) {
            self.map.insert(key.to_string(), value.to_string());
        }
        fn read(&self, key: &str) -> Option<&str> {
            if self.map.contains_key(key) {
                return Some(self.map[key].as_str());
            }
            None
        }
    }


    #[test]
    fn description() -> Result<(), InterpretError>{
        let code = r###"
if(description)
{
  script_oid("0.0.0.0.0.0.0.0.0.1");
  script_version("2022-11-14T13:47:12+0000");
  script_tag(name:"creation_date", value:"2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)");
  script_name("that is a very long and descriptive name");

# script_category values should be a keyword
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ssh_detect.nasl", "ssh2.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/blubb/detected");
  script_xref(name:"URL", value:"http://freshmeat.sourceforge.net/projects/eventh/");
  script_exclude_keys("Settings/disable_cgi_scanning", "bla/bla");
  #script_add_preference(name:"Enable Password", type:"password", value:"", id:2);
  script_require_udp_ports("Services/udp/unknown", 17);
  script_cve_id("CVE-1999-0524");
  script_require_keys("WMI/Apache/RootPath");
  exit(0);
}
        "###;
        let mut storage= MockStorage::new();
        let initial = vec![("description".to_owned(), ContextType::Value(NaslValue::Number(1)))];
        let mut interpret = Interpreter::new(&mut storage, initial, code);
        for stmt in parse(code) {
            let stmt = stmt?;
            assert_eq!(interpret.resolve(stmt)?, NaslValue::Exit(0));
        }
        assert_eq!(storage.read("oid"), Some("0.0.0.0.0.0.0.0.0.1"));
        // TODO same for the others
        Ok(())
    }

}