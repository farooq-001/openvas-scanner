use crate::{
    error::SyntaxError,
    lexer::{Lexer, End},
    token::{Category, Token},
    unclosed_token, unexpected_token, variable_extension::CommaGroup, Statement, AssignOrder,
};

pub(crate) trait Grouping {
    /// Parses (...)
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// Parses {...}
    fn parse_block(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// General Grouping parsing. Is called within prefix_extension.
    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError>;
}

impl<'a> Lexer<'a> {
    fn parse_brace(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.parse_comma_group(Category::RightBrace)?;
        if !end {
            Err(unclosed_token!(token))
        } else {
            Ok(Statement::Parameter(right))
        }
    }
}

impl<'a> Grouping for Lexer<'a> {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.statement(0, &|cat| cat == Category::RightParen)?;
        if !end {
            Err(unclosed_token!(token))
        } else {
            match right {
                Statement::Assign(category, _, variable, stmt) => Ok(Statement::Assign(
                    category,
                    AssignOrder::AssignReturn,
                    variable,
                    stmt,
                )),
                _ => Ok(right),
            }
        }
    }

    fn parse_block(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let mut results = vec![];
        while let Some(token) = self.peek() {
            if token.category() == Category::RightCurlyBracket {
                self.token();
                return Ok(Statement::Block(results));
            }
            let (end, stmt) = self.statement(0, &|cat| cat == Category::Semicolon)?;
            if end.is_done() && !matches!(stmt, Statement::NoOp(_)) {
                results.push(stmt);
            }
        }
        Err(unclosed_token!(token))
    }

    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        match token.category() {
            Category::LeftParen => self
                .parse_paren(token)
                .map(|stmt| (End::Continue, stmt)),
            Category::LeftCurlyBracket => self
                .parse_block(token)
                .map(|stmt| (End::Done(token.category()), stmt)),
            Category::LeftBrace => self
                .parse_brace(token)
                .map(|stmt| (End::Done(token.category()), stmt)),
            _ => Err(unexpected_token!(token)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        {AssignOrder, Statement},
        parse,
        token::{Base, Category, Token},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variables() {
        assert_eq!(
            result(
                r"
            {
                a = b + 1;
                b = a - --c;
                {
                   d = 23;
                }
            }
            "
            ),
            Block(vec![
                Assign(
                    Equal,
                    AssignOrder::AssignReturn,
                    Box::new(Variable(Token {
                        category: Identifier(None),
                        position: (31, 32)
                    })),
                    Box::new(Operator(
                        Plus,
                        vec![
                            Variable(Token {
                                category: Identifier(None),
                                position: (35, 36)
                            }),
                            Primitive(Token {
                                category: Number(Base10),
                                position: (39, 40)
                            })
                        ]
                    ))
                ),
                Assign(
                    Equal,
                    AssignOrder::AssignReturn,
                    Box::new(Variable(Token {
                        category: Identifier(None),
                        position: (58, 59)
                    },)),
                    Box::new(Operator(
                        Minus,
                        vec![
                            Variable(Token {
                                category: Identifier(None),
                                position: (62, 63)
                            }),
                            Assign(
                                MinusMinus,
                                AssignOrder::AssignReturn,
                                Box::new(Variable(Token {
                                    category: Identifier(None),
                                    position: (68, 69)
                                },)),
                                Box::new(NoOp(None))
                            )
                        ]
                    ))
                ),
                Block(vec![Assign(
                    Equal,
                    AssignOrder::AssignReturn,
                    Box::new(Variable(Token {
                        category: Identifier(None),
                        position: (108, 109)
                    },)),
                    Box::new(Primitive(Token {
                        category: Number(Base10),
                        position: (112, 114)
                    }))
                )])
            ])
        );
    }
}