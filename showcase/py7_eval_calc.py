def tokenize(expr):
    return expr.replace(" ", "")

def calculate(expr):
    expr = tokenize(expr)
    # VULNERABLE (line 6): code injection via eval
    return eval(expr)
