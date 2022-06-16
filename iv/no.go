package iv

type NoIvGenerator struct {
}

func (g NoIvGenerator) GenerateIv(int) ([]byte, error) {
	return make([]byte, 0), nil
}

func (g NoIvGenerator) IncludePlainIvInEncryptionResults() bool {
	return false
}
