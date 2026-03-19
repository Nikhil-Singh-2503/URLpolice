from urlpolice import URLPolice

police = URLPolice(perform_dns_resolution=True)
user_input = input("Enter a URL: ")

result = police.validate(user_input)
if result.is_valid:
    print("This is a valid URL")
else:
    print("This is not a valid URL")
print(result.__dict__)