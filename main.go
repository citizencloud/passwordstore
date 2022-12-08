package main

func main() {
	db, err := Open()
	if err != nil {
		panic(err)
	}
	db.List()
}
