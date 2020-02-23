import requests
import hashlib
import sys


def request_api_data(pwd_sha1):
    """Make request to the API

    Args:
        pwd_sha1 (string): Five character of sha1 password

    Raises:
        RuntimeError: raise error when response not 200

    Returns:
        int: The request reponse
    """
    url = 'https://api.pwnedpasswords.com/range/' + pwd_sha1
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check API and try again!')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    """Loop to all hashes to check password leaks

    Args:
        hashes (int): hashes(first 5 sha1 code)
        hash_to_check (int): The remaind of
            sha1 code (tail => secure in our machine - nobody can see that)
    """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """Check if password exists in API response

    Args:
        password (string): password given
    """
    sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_pwd[:5], sha1_pwd[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    """loop through passwords and tell us if your password is good or not

    Args:
        args (string): argument given
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...' +
                  'you should change you password')
        else:
            print(f'{password} was NOT FOUND. Carry on!')
    return 'Done!'


# Take all arguments after command 'python3'
main(sys.argv[1:])
