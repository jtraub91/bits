from typing import Tuple

from bits.blockchain import block_reward

chars = "abcdefghijklmnopqrstuvwxyz"

LAST = 2099999997689999
SUPPLY = 2099999997690000


def height(sat_: int) -> Tuple[int, int]:
    block_reward_for_halving = [block_reward(i * 210000) for i in range(0, 33)]

    total_supply = 0
    for epoch, reward in enumerate(block_reward_for_halving):
        max_total_reward = total_supply + (210000 * reward)
        if sat_ // max_total_reward:
            total_supply = max_total_reward
        else:
            blockheight = (epoch * 210000) + (sat_ - total_supply) // reward
            satheight = (sat_ - total_supply) % reward
            break

    return blockheight, satheight


def decimal(sat_: int) -> str:
    blockheight_, satheight_ = height(sat_)
    return f"{blockheight_}.{satheight_}"


def degree(sat_: int) -> str:
    blockheight_, satheight_ = height(sat_)
    cycle = blockheight_ // (210000 * 6)
    halving = blockheight_ % 210000
    diff_period = blockheight_ % 2016
    return f"{cycle}°{halving}′{diff_period}″{satheight_}‴"


def percentile(sat_: int, decimal_places: int = 16) -> str:
    return f"{format(100 * sat_ / LAST, f'0.{decimal_places}f')}%"


def name(sat_: int) -> str:
    _name = ""
    x = SUPPLY - sat_
    while x > 0:
        _name += chars[(x - 1) % 26]
        x = (x - 1) // 26
    return _name[::-1]


def from_name(name_: str) -> int:
    sat_ = 0
    for i, char in enumerate(name_):
        sat_ += (chars.index(char) + 1) * (26 ** (len(name_) - i - 1))
    return SUPPLY - sat_


def from_percentile(percentile_: str) -> int:
    return int(LAST * float(percentile_[:-1]) / 100)


def from_degree(degree_: str) -> int:
    cycle = int(degree_.split("°")[0])
    halving = int(degree_.split("'")[0].split("°")[1])
    diff_period = int(degree_.split("″")[0].split("′")[1])
    satheight = int(degree_.split("‴")[1])
    blockheight = (int(cycle) * 210000 * 6) + (int(halving) * 210000) + int(diff_period)
    return blockheight * block_reward(blockheight) + int(satheight)


def from_decimal(decimal_: str) -> int:
    blockheight, satheight = decimal_.split(".")
    blockheight = int(blockheight)
    satheight = int(satheight)
    supply = 0
    for i in range((blockheight // 210000) + 1):
        supply += min(210000, blockheight % 210000) * block_reward(i * 210000)
    return supply + satheight
