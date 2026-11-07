import ast
import base64
import sys

SAFE_CALLS = {
    "print", "len", "range", "sum", "min", "max", "abs", "round",
    "sorted", "enumerate", "zip", "all", "any", "str", "int", "float",
    "bool", "list", "tuple", "dict", "set", "repr", "ord", "chr",
    "hex", "bin", "oct", "divmod", "pow",
}
SAFE_NODES = (
    ast.Module, ast.Expr, ast.Assign, ast.Name, ast.Load, ast.Store,
    ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set,
    ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp,
    ast.Call, ast.keyword, ast.Subscript, ast.Slice,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.USub, ast.UAdd, ast.Not, ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.comprehension,
    ast.For, ast.If, ast.Break, ast.Continue, ast.Pass,
)

def validate(node):
    for item in ast.walk(node):
        if not isinstance(item, SAFE_NODES):
            raise ValueError("Bu Python dil yapısına izin verilmiyor: " + type(item).__name__)
        if isinstance(item, ast.Name):
            if item.id.startswith("_"):
                raise ValueError("Özel isimlere erişim engellendi.")
            if isinstance(item.ctx, ast.Load) and item.id not in SAFE_CALLS and item.id not in {"True", "False", "None"}:
                # User variables are permitted if assigned in this module.
                pass
        if isinstance(item, ast.Call):
            if not isinstance(item.func, ast.Name) or item.func.id not in SAFE_CALLS:
                raise ValueError("Yalnızca izin verilen yerleşik fonksiyonlar çağrılabilir.")
        if isinstance(item, ast.Assign):
            if any(not isinstance(t, (ast.Name, ast.Tuple, ast.List)) for t in item.targets):
                raise ValueError("Bu atama hedefi desteklenmiyor.")
    return node

def main():
    if len(sys.argv) != 2:
        raise ValueError("Kod parametresi eksik.")
    source = base64.b64decode(sys.argv[1], validate=True).decode("utf-8")
    if not source.strip() or len(source) > 2000:
        raise ValueError("Kod boş veya uzunluk sınırını aşıyor.")
    tree = validate(ast.parse(source, mode="exec"))
    safe_builtins = {name: getattr(__builtins__, name) if not isinstance(__builtins__, dict) else __builtins__[name] for name in SAFE_CALLS}
    scope = {"__builtins__": safe_builtins}
    exec(compile(tree, "<neora-user-code>", "exec"), scope, scope)

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("POLICY/RUNTIME ERROR:", str(exc)[:300], file=sys.stderr)
        sys.exit(2)
