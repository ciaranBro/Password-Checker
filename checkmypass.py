import requests 
import hashlib
import sys 

#define function requesting API data
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    #check status code and raise error if it's not 200
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
#check password if it exists in API response 
    shapassword1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    firs5_char, tail = shapassword1[:5], shapassword1[5:]
    response = request_api_data(firs5_char)
    print(firs5_char, tail)
    return get_password_leaks_count(response, tail)

# pwned_api_check('123')

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'The password {password} was found {count} many times, you should probably change it!')
        else:
            print(f'The password {password} was NOT found, carry on!')
    return 'done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
