from typing import List


# Because built in realization in package bisect returns
# position of place to insert desired value, if it's missing,
# there's default realization of binary search returns -1, if value is missing.
def binary_search(sequence: List[int], value: int) -> int:
    """looks for value in sorted sequence and returns its index if it exists"""
    left: int = 0
    right: int = len(sequence) - 1
    while left <= right:
        mid: int = left + (right - left) // 2
        if sequence[mid] == value:
            return mid
        if sequence[mid] > value:
            right = mid - 1
        else:
            left = mid + 1
    return -1
