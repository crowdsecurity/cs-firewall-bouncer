package pf

func chunkItems[T any](items []T, chunkSize int) [][]T {
	// optimization for small slices
	if len(items) <= chunkSize {
		if len(items) == 0 {
			return [][]T{}
		}
		return [][]T{items}
	}

	var ret [][]T
	chunk := make([]T, 0, chunkSize)

	for _, v := range items {
		chunk = append(chunk, v)
		if len(chunk) == chunkSize {
			ret = append(ret, chunk)
			chunk = nil
		}
	}
	if len(chunk) > 0 {
		ret = append(ret, chunk)
	}
	return ret
}
