package structs

type ports = map[string]string

type Data struct {
	Attack string `json:"attack"`
	Ports  ports  `json:"ports"`
	Server string `json:"server"`
	User   string `json:"user"`
	Pass   string `json:"pass"`
}

type Results struct {
	Success   bool    `json:"success"`
	TotalTime float64 `json:"time"`
}
