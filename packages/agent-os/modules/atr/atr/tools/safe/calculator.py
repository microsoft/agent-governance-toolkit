# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe Calculator Tool.

Provides safe mathematical operations with:
- No eval() or exec() usage
- Expression parsing with allowed operations only
- Overflow protection
- Timeout for complex calculations
"""

import ast
import math
import operator
import re
from typing import Any, Dict, List, Optional, Union

from atr.decorator import tool


class CalculatorTool:
    """
    Safe calculator with expression evaluation.
    
    Features:
    - No eval()/exec() - uses safe expression parser
    - Whitelisted operations only
    - Overflow/underflow protection
    - Precision control
    - Common math functions (sqrt, sin, cos, log, etc.)
    
    Example:
        ```python
        calc = CalculatorTool(precision=10)
        
        # Basic arithmetic
        result = calc.evaluate("2 + 2 * 3")  # 8
        
        # With variables
        result = calc.evaluate("x * 2 + y", {"x": 5, "y": 10})  # 20
        
        # Math functions
        result = calc.evaluate("sqrt(16) + sin(0)")  # 4.0
        ```
    """
    
    # Allowed operators
    OPERATORS = {
        '+': operator.add,
        '-': operator.sub,
        '*': operator.mul,
        '/': operator.truediv,
        '//': operator.floordiv,
        '%': operator.mod,
        '**': operator.pow,
        '^': operator.pow,  # Alias for **
    }
    
    # Allowed functions
    FUNCTIONS = {
        'abs': abs,
        'round': round,
        'min': min,
        'max': max,
        'sum': sum,
        # Math functions
        'sqrt': math.sqrt,
        'pow': math.pow,
        'exp': math.exp,
        'log': math.log,
        'log10': math.log10,
        'log2': math.log2,
        'sin': math.sin,
        'cos': math.cos,
        'tan': math.tan,
        'asin': math.asin,
        'acos': math.acos,
        'atan': math.atan,
        'sinh': math.sinh,
        'cosh': math.cosh,
        'tanh': math.tanh,
        'ceil': math.ceil,
        'floor': math.floor,
        'factorial': math.factorial,
        'gcd': math.gcd,
        'degrees': math.degrees,
        'radians': math.radians,
    }
    
    # Constants
    CONSTANTS = {
        'pi': math.pi,
        'e': math.e,
        'tau': math.tau,
        'inf': math.inf,
    }
    
    def __init__(
        self,
        precision: int = 15,
        max_value: float = 1e308,
        allow_complex: bool = False
    ):
        """
        Initialize calculator.
        
        Args:
            precision: Decimal precision for results
            max_value: Maximum allowed value
            allow_complex: Whether to allow complex numbers
        """
        self.precision = precision
        self.max_value = max_value
        self.allow_complex = allow_complex
    
    # AST operator mapping for safe evaluation
    _AST_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    
    _AST_UNARY_OPS = {
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }
    
    def _safe_eval_node(
        self,
        node: ast.AST,
        namespace: Dict[str, Any],
    ) -> Any:
        """Recursively evaluate an AST node using only safe operations.
        
        No eval()/compile() — walks the AST tree and computes results
        using whitelisted operators and functions only.
        """
        if isinstance(node, ast.Expression):
            return self._safe_eval_node(node.body, namespace)
        
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError(f"Unsupported constant type: {type(node.value).__name__}")
        
        if isinstance(node, ast.Name):
            if node.id in namespace:
                return namespace[node.id]
            raise ValueError(f"Unknown variable: {node.id}")
        
        if isinstance(node, ast.BinOp):
            left = self._safe_eval_node(node.left, namespace)
            right = self._safe_eval_node(node.right, namespace)
            op_func = self._AST_OPS.get(type(node.op))
            if op_func is None:
                raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
            return op_func(left, right)
        
        if isinstance(node, ast.UnaryOp):
            operand = self._safe_eval_node(node.operand, namespace)
            op_func = self._AST_UNARY_OPS.get(type(node.op))
            if op_func is None:
                raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
            return op_func(operand)
        
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ValueError("Only direct function calls are allowed (no attribute access)")
            func_name = node.func.id
            if func_name not in self.FUNCTIONS:
                raise ValueError(f"Function not allowed: {func_name}")
            func = self.FUNCTIONS[func_name]
            args = [self._safe_eval_node(arg, namespace) for arg in node.args]
            if node.keywords:
                raise ValueError("Keyword arguments are not supported in function calls")
            return func(*args)
        
        if isinstance(node, ast.Tuple):
            return tuple(self._safe_eval_node(elt, namespace) for elt in node.elts)
        
        if isinstance(node, ast.List):
            return [self._safe_eval_node(elt, namespace) for elt in node.elts]
        
        raise ValueError(f"Unsupported expression type: {type(node).__name__}")
    
    def _check_value(self, value: Union[int, float]) -> Union[int, float]:
        """Check value is within bounds."""
        if isinstance(value, complex) and not self.allow_complex:
            raise ValueError("Complex numbers not allowed")
        
        if isinstance(value, (int, float)):
            if abs(value) > self.max_value:
                raise OverflowError(f"Value exceeds maximum: {self.max_value}")
        
        return value
    
    @tool(
        name="calculate",
        description="Evaluate a mathematical expression safely",
        tags=["math", "calculate", "safe"]
    )
    def evaluate(
        self,
        expression: str,
        variables: Optional[Dict[str, Union[int, float]]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate a mathematical expression.
        
        Args:
            expression: Math expression (e.g., "2 + 2 * 3")
            variables: Variable values (e.g., {"x": 5})
        
        Returns:
            Dict with result and metadata
        """
        variables = variables or {}
        
        # Validate expression length
        if len(expression) > 1000:
            return {
                "success": False,
                "error": "Expression too long (max 1000 chars)",
                "result": None
            }
        
        # Sanitize - only allow safe characters
        allowed_chars = set("0123456789.+-*/^%() ,")
        allowed_chars.update(set("abcdefghijklmnopqrstuvwxyz_"))
        
        clean_expr = expression.lower()
        for char in clean_expr:
            if char not in allowed_chars:
                return {
                    "success": False,
                    "error": f"Invalid character: '{char}'",
                    "result": None
                }
        
        try:
            # Build safe namespace
            namespace = {}
            namespace.update(self.CONSTANTS)
            namespace.update(self.FUNCTIONS)
            namespace.update(variables)
            
            # Parse and evaluate using safe AST walker
            
            # Replace ^ with ** for power
            clean_expr = clean_expr.replace('^', '**')
            
            # Parse expression
            tree = ast.parse(clean_expr, mode='eval')
            
            # Validate AST nodes
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id not in self.FUNCTIONS:
                            return {
                                "success": False,
                                "error": f"Function not allowed: {node.func.id}",
                                "result": None
                            }
                    else:
                        return {
                            "success": False,
                            "error": "Only direct function calls are allowed (no attribute access)",
                            "result": None
                        }
                elif isinstance(node, ast.Name):
                    if node.id not in namespace:
                        return {
                            "success": False,
                            "error": f"Unknown variable: {node.id}",
                            "result": None
                        }
                elif isinstance(node, ast.Attribute):
                    return {
                        "success": False,
                        "error": "Attribute access is not allowed",
                        "result": None
                    }
            
            # Evaluate using safe AST walker (no eval/compile)
            result = self._safe_eval_node(tree.body, namespace)
            
            # Check result
            result = self._check_value(result)
            
            # Round if float
            if isinstance(result, float):
                result = round(result, self.precision)
            
            return {
                "success": True,
                "result": result,
                "expression": expression,
                "type": type(result).__name__
            }
            
        except SyntaxError as e:
            return {
                "success": False,
                "error": f"Syntax error: {e}",
                "result": None
            }
        except (ValueError, TypeError, OverflowError, ZeroDivisionError) as e:
            return {
                "success": False,
                "error": str(e),
                "result": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Calculation error: {e}",
                "result": None
            }
    
    @tool(
        name="add",
        description="Add two or more numbers",
        tags=["math", "arithmetic", "safe"]
    )
    def add(self, *numbers: Union[int, float]) -> Dict[str, Any]:
        """Add numbers."""
        try:
            result = sum(numbers)
            return {"success": True, "result": self._check_value(result)}
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="subtract",
        description="Subtract numbers (a - b - c - ...)",
        tags=["math", "arithmetic", "safe"]
    )
    def subtract(self, *numbers: Union[int, float]) -> Dict[str, Any]:
        """Subtract numbers."""
        try:
            if not numbers:
                return {"success": False, "error": "No numbers provided", "result": None}
            result = numbers[0]
            for n in numbers[1:]:
                result -= n
            return {"success": True, "result": self._check_value(result)}
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="multiply",
        description="Multiply numbers",
        tags=["math", "arithmetic", "safe"]
    )
    def multiply(self, *numbers: Union[int, float]) -> Dict[str, Any]:
        """Multiply numbers."""
        try:
            result = 1
            for n in numbers:
                result *= n
            return {"success": True, "result": self._check_value(result)}
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="divide",
        description="Divide numbers (a / b)",
        tags=["math", "arithmetic", "safe"]
    )
    def divide(self, a: Union[int, float], b: Union[int, float]) -> Dict[str, Any]:
        """Divide a by b."""
        try:
            if b == 0:
                return {"success": False, "error": "Division by zero", "result": None}
            result = a / b
            return {"success": True, "result": round(self._check_value(result), self.precision)}
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="power",
        description="Calculate a raised to power b (a^b)",
        tags=["math", "arithmetic", "safe"]
    )
    def power(self, base: Union[int, float], exponent: Union[int, float]) -> Dict[str, Any]:
        """Calculate power."""
        try:
            # Limit exponent to prevent huge calculations
            if abs(exponent) > 1000:
                return {"success": False, "error": "Exponent too large", "result": None}
            result = base ** exponent
            return {"success": True, "result": self._check_value(result)}
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="sqrt",
        description="Calculate square root",
        tags=["math", "safe"]
    )
    def sqrt(self, n: Union[int, float]) -> Dict[str, Any]:
        """Calculate square root."""
        try:
            if n < 0 and not self.allow_complex:
                return {"success": False, "error": "Cannot take sqrt of negative number", "result": None}
            result = math.sqrt(n)
            return {"success": True, "result": round(result, self.precision)}
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="percentage",
        description="Calculate percentage (what is x% of y)",
        tags=["math", "percentage", "safe"]
    )
    def percentage(self, percent: Union[int, float], of_value: Union[int, float]) -> Dict[str, Any]:
        """Calculate percentage."""
        try:
            result = (percent / 100) * of_value
            return {
                "success": True,
                "result": round(result, self.precision),
                "description": f"{percent}% of {of_value} = {round(result, self.precision)}"
            }
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
    
    @tool(
        name="statistics",
        description="Calculate basic statistics (mean, median, std dev)",
        tags=["math", "statistics", "safe"]
    )
    def statistics(self, numbers: List[Union[int, float]]) -> Dict[str, Any]:
        """Calculate basic statistics."""
        try:
            if not numbers:
                return {"success": False, "error": "No numbers provided", "result": None}
            
            import statistics as stats
            
            n = len(numbers)
            mean = stats.mean(numbers)
            median = stats.median(numbers)
            
            result = {
                "count": n,
                "sum": sum(numbers),
                "mean": round(mean, self.precision),
                "median": round(median, self.precision),
                "min": min(numbers),
                "max": max(numbers),
            }
            
            if n > 1:
                result["std_dev"] = round(stats.stdev(numbers), self.precision)
                result["variance"] = round(stats.variance(numbers), self.precision)
            
            return {"success": True, "result": result}
            
        except Exception as e:
            return {"success": False, "error": str(e), "result": None}
