"""Pure utility functions — no I/O, no syscalls, no network."""


def add(a: int, b: int) -> int:
    return a + b


def multiply(a: int, b: int) -> int:
    return a * b


def divide(a: float, b: float) -> float:
    if b == 0.0:
        raise ZeroDivisionError("cannot divide by zero")
    return a / b


def average(numbers: list[float]) -> float:
    if not numbers:
        raise ValueError("cannot average an empty list")
    return sum(numbers) / len(numbers)
